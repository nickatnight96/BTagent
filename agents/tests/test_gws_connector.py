"""Unit tests for the Google Workspace MCP connector (#100 Tier-1 slice).

Mirrors the Okta (#212) / Entra (#221) test suites so the three Tier-1
identity connectors are exercised symmetrically.

Coverage:
- Login activity JSON → :class:`IdentityEvent` normalisation across
  LOGIN_SUCCESS, LOGIN_FAILURE, 2SV challenge / deny / approve.
- Admin + token activity JSON → :class:`IdentityEvent` normalisation across
  role assignment, domain-wide delegation, SSO toggle, password change, and
  OAuth token authorize/revoke; unmapped events dropped.
- Directory token JSON → :class:`OAuthGrant` normalisation including the
  timestamp-enrichment convention and the anonymous (unverified-app) case.
- Events ↔ grants join on stable (principal_id, app_id) for the dormant-grant
  detector — the Codex #212 join discipline applied to Workspace shapes.
- Cross-provider detector smoke: the same #116 detectors fire on
  Workspace-normalised fixtures (MFA fatigue + dormant-app reactivation).
- Circuit-breaker open/close behaviour via :class:`MCPConnectionRegistry`.
- Secret-redaction: the service-account key never appears in logs / repr.
- Discovery registration alongside the existing Tier-1 connectors.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest
from btagent_shared.hunt.identity import (
    detect_dormant_app_reactivation,
    detect_mfa_fatigue,
)
from btagent_shared.types.identity_hunt import (
    IdentityEvent,
    IdentityEventKind,
    IdentityProvider,
    OAuthConsentType,
    OAuthGrant,
)
from btagent_shared.types.mcp import MCPServerConfig

from btagent_agents.mcp.registry import (
    CircuitOpenError,
    CircuitState,
    MCPConnectionRegistry,
)
from btagent_agents.mcp.servers._gws_fixtures import (
    GWS_FIXTURE_AUDIT_EVENTS,
    GWS_FIXTURE_LOGIN_EVENTS,
    GWS_FIXTURE_TOKENS,
)
from btagent_agents.mcp.servers.gws_mcp import (
    GWS_EVENT_MAP,
    GoogleWorkspaceMCPServer,
    _redact_secret,
    normalise_audit_event,
    normalise_login_event,
    normalise_oauth_token,
)

ORG = "org_test"

# Fixture window covering every recorded event.
WINDOW_START = "2026-06-01T00:00:00Z"
WINDOW_END = "2026-06-02T00:00:00Z"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_login(qualifier: str) -> dict[str, Any]:
    for evt in GWS_FIXTURE_LOGIN_EVENTS:
        if (evt.get("id") or {}).get("uniqueQualifier") == qualifier:
            return evt
    raise AssertionError(f"login fixture {qualifier} not found")


def _find_audit_by_name(name: str) -> dict[str, Any]:
    for evt in GWS_FIXTURE_AUDIT_EVENTS:
        if (evt.get("events") or [{}])[0].get("name") == name:
            return evt
    raise AssertionError(f"audit fixture {name} not found")


def _all_login_events() -> list[IdentityEvent]:
    return [normalise_login_event(e, org_id=ORG) for e in GWS_FIXTURE_LOGIN_EVENTS]


def _all_audit_events() -> list[IdentityEvent]:
    return [
        ev
        for ev in (normalise_audit_event(e, org_id=ORG) for e in GWS_FIXTURE_AUDIT_EVENTS)
        if ev is not None
    ]


def _all_grants() -> list[OAuthGrant]:
    return [normalise_oauth_token(t, org_id=ORG) for t in GWS_FIXTURE_TOKENS]


# ---------------------------------------------------------------------------
# Login normalisation
# ---------------------------------------------------------------------------


class TestLoginNormalisation:
    def test_login_success_normalises(self) -> None:
        ev = normalise_login_event(_find_login("-900000000000000005"), org_id=ORG)
        assert ev.kind is IdentityEventKind.LOGIN_SUCCESS
        assert ev.provider is IdentityProvider.GOOGLE_WORKSPACE
        assert ev.principal_id == "bob@example.com"
        assert ev.ip_address == "198.51.100.20"
        assert ev.org_id == ORG

    def test_login_failure_normalises(self) -> None:
        ev = normalise_login_event(_find_login("-900000000000000006"), org_id=ORG)
        assert ev.kind is IdentityEventKind.LOGIN_FAILURE

    def test_2sv_failed_maps_to_mfa_denied(self) -> None:
        ev = normalise_login_event(_find_login("-900000000000000001"), org_id=ORG)
        assert ev.kind is IdentityEventKind.MFA_DENIED

    def test_2sv_passed_maps_to_mfa_approved(self) -> None:
        ev = normalise_login_event(_find_login("-900000000000000004"), org_id=ORG)
        assert ev.kind is IdentityEventKind.MFA_APPROVED

    def test_2sv_without_status_maps_to_mfa_challenge(self) -> None:
        raw = {
            "id": {"time": "2026-06-01T09:00:00.000Z", "uniqueQualifier": "-1"},
            "actor": {"email": "alice@example.com"},
            "events": [{"type": "login", "name": "login_verification", "parameters": []}],
        }
        ev = normalise_login_event(raw, org_id=ORG)
        assert ev.kind is IdentityEventKind.MFA_CHALLENGE

    def test_normaliser_preserves_raw_payload(self) -> None:
        raw = _find_login("-900000000000000005")
        ev = normalise_login_event(raw, org_id=ORG)
        assert ev.raw == raw


# ---------------------------------------------------------------------------
# Admin / token audit normalisation
# ---------------------------------------------------------------------------


class TestAuditNormalisation:
    def test_role_assignment_classified(self) -> None:
        ev = normalise_audit_event(_find_audit_by_name("ASSIGN_ROLE"), org_id=ORG)
        assert ev is not None
        assert ev.kind is IdentityEventKind.ROLE_ASSIGNED
        assert ev.principal_id == "admin@example.com"

    def test_domain_wide_delegation_classified_with_app_id(self) -> None:
        ev = normalise_audit_event(_find_audit_by_name("AUTHORIZE_API_CLIENT_ACCESS"), org_id=ORG)
        assert ev is not None
        assert ev.kind is IdentityEventKind.APP_CONSENT_GRANTED
        # Delegation events surface the API client id as the join key.
        assert ev.app_id.endswith("mailsync.apps.googleusercontent.com")

    def test_sso_toggle_classified_as_federation_change(self) -> None:
        ev = normalise_audit_event(_find_audit_by_name("TOGGLE_SSO_ENABLED"), org_id=ORG)
        assert ev is not None
        assert ev.kind is IdentityEventKind.FEDERATION_TRUST_MODIFIED

    def test_password_change_classified(self) -> None:
        ev = normalise_audit_event(_find_audit_by_name("CHANGE_PASSWORD"), org_id=ORG)
        assert ev is not None
        assert ev.kind is IdentityEventKind.CREDENTIAL_ADDED

    def test_token_authorize_carries_client_id(self) -> None:
        ev = normalise_audit_event(_find_audit_by_name("authorize"), org_id=ORG)
        assert ev is not None
        assert ev.kind is IdentityEventKind.GRANT_CREATED
        assert ev.app_id.endswith("mailsync.apps.googleusercontent.com")
        assert ev.principal_id == "alice@example.com"

    def test_token_revoke_classified(self) -> None:
        ev = normalise_audit_event(_find_audit_by_name("revoke"), org_id=ORG)
        assert ev is not None
        assert ev.kind is IdentityEventKind.GRANT_REVOKED

    def test_unknown_event_returns_none(self) -> None:
        ev = normalise_audit_event(_find_audit_by_name("CHANGE_CALENDAR_SETTING"), org_id=ORG)
        assert ev is None

    def test_event_map_covers_only_known_names(self) -> None:
        # Every mapped name is a stable Reports identifier — no prose.
        for name in GWS_EVENT_MAP:
            assert " " not in name


# ---------------------------------------------------------------------------
# OAuth token → grant normalisation
# ---------------------------------------------------------------------------


class TestOAuthTokenNormalisation:
    def test_user_token_normalises(self) -> None:
        grant = _all_grants()[0]
        assert grant.provider is IdentityProvider.GOOGLE_WORKSPACE
        assert grant.principal_id == "alice@example.com"
        assert grant.app_id.endswith("mailsync.apps.googleusercontent.com")
        assert grant.consent_type is OAuthConsentType.USER
        assert "https://mail.google.com/" in grant.scopes

    def test_enrichment_timestamps_parsed(self) -> None:
        grant = _all_grants()[0]
        assert grant.granted_at.year == 2025
        assert grant.last_used is not None and grant.last_used.year == 2026

    def test_anonymous_app_maps_to_unknown_consent(self) -> None:
        anon = [g for g in _all_grants() if g.app_display_name == "Unverified Drive Utility"]
        assert anon and anon[0].consent_type is OAuthConsentType.UNKNOWN

    def test_missing_last_used_yields_none(self) -> None:
        anon = [g for g in _all_grants() if g.app_display_name == "Unverified Drive Utility"]
        assert anon[0].last_used is None

    def test_grant_and_event_share_join_key(self) -> None:
        """The dormant-grant detector joins on (principal_id, app_id)."""
        grant = _all_grants()[0]
        authorize = normalise_audit_event(_find_audit_by_name("authorize"), org_id=ORG)
        assert authorize is not None
        assert (grant.principal_id, grant.app_id) == (
            authorize.principal_id,
            authorize.app_id,
        )


# ---------------------------------------------------------------------------
# Cross-provider detector smoke — same #116 detectors, Workspace data
# ---------------------------------------------------------------------------


class TestDetectorSmoke:
    def test_mfa_fatigue_fires_on_gws_fixtures(self) -> None:
        results = detect_mfa_fatigue(_all_login_events())
        assert len(results) == 1
        assert "alice@example.com" in results[0].title or "alice" in str(results[0].evidence)

    def test_dormant_app_reactivation_fires_on_gws_fixtures(self) -> None:
        results = detect_dormant_app_reactivation(_all_grants(), _all_audit_events())
        assert len(results) == 1
        evidence = results[0].evidence
        assert evidence.get("principal_id") == "alice@example.com"
        assert str(evidence.get("app_id", "")).endswith("mailsync.apps.googleusercontent.com")


# ---------------------------------------------------------------------------
# Mock envelopes
# ---------------------------------------------------------------------------


class TestMockEnvelopes:
    async def test_login_search_returns_normalised_events(self) -> None:
        server = GoogleWorkspaceMCPServer(mock_mode=True)
        out = await server.gws_login_activity_search(WINDOW_START, WINDOW_END)
        assert out["status"] == "success" and out["is_mock"] is True
        assert out["total"] == len(GWS_FIXTURE_LOGIN_EVENTS)
        assert len(out["events"]) == out["total"]
        assert all(e["provider"] == "google_workspace" for e in out["events"])

    async def test_login_search_respects_time_window(self) -> None:
        server = GoogleWorkspaceMCPServer(mock_mode=True)
        out = await server.gws_login_activity_search("2026-06-01T10:00:00Z", "2026-06-01T10:01:00Z")
        assert out["total"] == 1
        assert out["events"][0]["kind"] == "login_success"

    async def test_login_filter_narrows_by_email(self) -> None:
        server = GoogleWorkspaceMCPServer(mock_mode=True)
        out = await server.gws_login_activity_search(WINDOW_START, WINDOW_END, filter="bob@")
        assert out["total"] == 2
        assert all("bob@" in (e["actor"]["email"]) for e in out["events_raw"])

    async def test_audit_search_drops_unmapped_events(self) -> None:
        server = GoogleWorkspaceMCPServer(mock_mode=True)
        out = await server.gws_audit_activity_search(WINDOW_START, WINDOW_END)
        # Raw keeps everything in-window; normalised drops the calendar event.
        assert out["total"] == len(GWS_FIXTURE_AUDIT_EVENTS)
        assert len(out["events"]) == out["total"] - 1

    async def test_audit_event_filter_narrows_results(self) -> None:
        server = GoogleWorkspaceMCPServer(mock_mode=True)
        out = await server.gws_audit_activity_search(
            WINDOW_START, WINDOW_END, event_filter="ASSIGN_ROLE"
        )
        assert out["total"] == 1

    async def test_list_tokens_returns_all(self) -> None:
        server = GoogleWorkspaceMCPServer(mock_mode=True)
        out = await server.gws_list_oauth_tokens()
        assert out["total"] == len(GWS_FIXTURE_TOKENS)
        assert all(g["provider"] == "google_workspace" for g in out["grants"])

    async def test_list_tokens_filters_by_email(self) -> None:
        server = GoogleWorkspaceMCPServer(mock_mode=True)
        out = await server.gws_list_oauth_tokens(user_email="bob@example.com")
        assert out["total"] == 1
        assert out["grants"][0]["principal_id"] == "bob@example.com"

    async def test_login_limit_caps_event_count(self) -> None:
        server = GoogleWorkspaceMCPServer(mock_mode=True)
        out = await server.gws_login_activity_search(WINDOW_START, WINDOW_END, limit=2)
        assert out["total"] == 2


# ---------------------------------------------------------------------------
# Live mode refuses without a key
# ---------------------------------------------------------------------------


class TestLiveModeRefusesWithoutKey:
    async def test_live_mode_without_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_GWS_SA_KEY", raising=False)
        server = GoogleWorkspaceMCPServer(mock_mode=False, sa_key_ref="${env:BTAGENT_GWS_SA_KEY}")
        with pytest.raises(NotImplementedError):
            await server.gws_login_activity_search(WINDOW_START, WINDOW_END)
        with pytest.raises(NotImplementedError):
            await server.gws_audit_activity_search(WINDOW_START, WINDOW_END)
        with pytest.raises(NotImplementedError):
            await server.gws_list_oauth_tokens()

    async def test_live_mode_real_path_not_yet_implemented(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BTAGENT_GWS_SA_KEY", "sa-key-material-0123456789abcdef")
        server = GoogleWorkspaceMCPServer(mock_mode=False, sa_key_ref="${env:BTAGENT_GWS_SA_KEY}")
        with pytest.raises(NotImplementedError):
            await server.gws_login_activity_search(WINDOW_START, WINDOW_END)


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_repr_omits_secret(self) -> None:
        server = GoogleWorkspaceMCPServer(mock_mode=False, sa_key_ref="${env:BTAGENT_GWS_SA_KEY}")
        assert "sa-key" not in repr(server)
        assert "secret" not in repr(server).lower() or "ref" in repr(server).lower()

    def test_redact_secret_short_returns_placeholder(self) -> None:
        assert _redact_secret("short") == "[redacted]"
        assert _redact_secret("") == "[redacted]"

    def test_redact_secret_long_returns_fingerprint(self) -> None:
        out = _redact_secret("sa-key-material-0123456789abcdef")
        assert out.startswith("[redacted:gws-sa-key:")
        assert "sa-key-material" not in out

    async def test_live_mode_log_lines_redact_secret(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.delenv("BTAGENT_GWS_SA_KEY", raising=False)
        server = GoogleWorkspaceMCPServer(mock_mode=False, sa_key_ref="${env:BTAGENT_GWS_SA_KEY}")
        with caplog.at_level(logging.WARNING, logger="btagent.mcp.servers.gws"):
            with pytest.raises(NotImplementedError):
                await server.gws_login_activity_search(WINDOW_START, WINDOW_END)
        for record in caplog.records:
            assert "BTAGENT_GWS_SA_KEY" not in record.getMessage() or "unresolved" in (
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
            name="gws",
            description="gws test",
            circuit_breaker_threshold=3,
            circuit_breaker_recovery=60,
        )
        conn = await registry.get_connection("gws", config=cfg, consumer_id="inv_test")
        assert conn.circuit_breaker.state is CircuitState.CLOSED

        for _ in range(3):
            registry.record_failure("gws", RuntimeError("simulated 503"))
        assert conn.circuit_breaker.state is CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            conn.circuit_breaker.check_state()


# ---------------------------------------------------------------------------
# Discovery registration + construction hygiene
# ---------------------------------------------------------------------------


class TestDiscoveryRegistration:
    def test_gws_server_registered_in_discovery(self) -> None:
        from btagent_agents.mcp import discovery

        discovery._ensure_servers_loaded()
        assert "gws" in discovery._SERVER_CLASSES
        assert discovery._SERVER_CLASSES["gws"] is GoogleWorkspaceMCPServer

    def test_tool_metadata_marks_gws_server(self) -> None:
        server = GoogleWorkspaceMCPServer(mock_mode=True)
        meta = server.get_tool_metadata()
        assert {m["name"] for m in meta} == {
            "gws_login_activity_search",
            "gws_audit_activity_search",
            "gws_list_oauth_tokens",
        }
        assert all(m["server_id"] == "gws" for m in meta)


def test_construction_does_not_resolve_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructing the server must never read the secret ref (lazy resolution)."""
    calls: list[str] = []

    def _spy(ref: str) -> str:
        calls.append(ref)
        return ""

    monkeypatch.setattr("btagent_agents.mcp.servers.gws_mcp.resolve_secret", _spy)
    GoogleWorkspaceMCPServer(mock_mode=False)
    assert calls == []
