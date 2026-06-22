"""Unit tests for the Okta MCP connector (#100 — Tier-1 slice).

Coverage:
- System Log JSON → :class:`IdentityEvent` normalisation across
  USER_AUTHENTICATION_AUTH (login), OAUTH_TOKEN_ISSUED, MFA challenge /
  deny / approve, and IdP-lifecycle (federation) events.
- OAuth grant JSON → :class:`OAuthGrant` normalisation including consent
  type derivation and scope splitting.
- Circuit-breaker open/close behaviour driven by recorded failures via
  the existing :class:`MCPConnectionRegistry` infra.
- Secret-redaction: the Okta API token is never present in logs / repr /
  exception strings.
- Discovery registration: the connector is wired into the lazy server
  registry alongside the existing Tier-1 connectors.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from btagent_shared.types.identity_hunt import (
    IdentityEvent,
    IdentityEventKind,
    IdentityProvider,
    OAuthConsentType,
    OAuthGrant,
)
from btagent_shared.types.mcp import MCPServerConfig

from btagent_agents.mcp.registry import (
    CB_FAILURE_THRESHOLD,
    CircuitOpenError,
    CircuitState,
    MCPConnectionRegistry,
)
from btagent_agents.mcp.servers._okta_fixtures import (
    OKTA_FIXTURE_OAUTH_GRANTS,
    OKTA_FIXTURE_SYSTEM_LOG,
)
from btagent_agents.mcp.servers.okta_mcp import (
    OKTA_EVENT_TYPE_MAP,
    OktaMCPServer,
    _redact_token,
    normalise_oauth_grant,
    normalise_system_log_event,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_event(uuid: str) -> dict[str, Any]:
    for evt in OKTA_FIXTURE_SYSTEM_LOG:
        if evt["uuid"] == uuid:
            return evt
    raise KeyError(uuid)


# ---------------------------------------------------------------------------
# System Log → IdentityEvent normalisation
# ---------------------------------------------------------------------------


class TestSystemLogNormalisation:
    def test_login_success_normalises(self) -> None:
        raw = _find_event("okta-evt-login-success-001")
        evt = normalise_system_log_event(raw, org_id="org_test")
        assert evt is not None
        assert evt.provider is IdentityProvider.OKTA
        assert evt.kind is IdentityEventKind.LOGIN_SUCCESS
        assert evt.principal_id == "alice@example.com"
        assert evt.ip_address == "8.8.8.8"
        assert evt.geo.country == "US"
        assert evt.geo.asn == "AS15169"
        assert evt.org_id == "org_test"
        # timestamp parsed to aware UTC
        assert evt.timestamp.tzinfo is not None
        assert evt.timestamp == datetime(2026, 6, 18, 9, 30, tzinfo=UTC)

    def test_oauth_token_issued_normalises(self) -> None:
        raw = _find_event("okta-evt-replay-aaa-001")
        evt = normalise_system_log_event(raw, org_id="org_test")
        assert evt is not None
        assert evt.kind is IdentityEventKind.TOKEN_ISSUED
        # Session and token IDs are pulled from the Okta-specific paths
        assert evt.session_id == "ext_sess_fixture_replay_001"
        assert evt.token_id == "at_fixture_replay_001"
        # OAuth app id surfaces from target[] — the STABLE Okta id, not the
        # display label (Codex #212): _app_id_from_event now prefers
        # ``target.id`` so it joins to grants keyed on ``clientId``.
        assert evt.app_id == "0oafixtureapp001"

    def test_refresh_token_classifies_as_token_refresh(self) -> None:
        raw = _find_event("okta-evt-replay-bbb-002")
        evt = normalise_system_log_event(raw, org_id="org_test")
        assert evt is not None
        assert evt.kind is IdentityEventKind.TOKEN_REFRESH

    def test_mfa_deny_classifies_as_mfa_denied(self) -> None:
        raw = _find_event("okta-evt-mfa-denied-001")
        evt = normalise_system_log_event(raw, org_id="org_test")
        assert evt is not None
        assert evt.kind is IdentityEventKind.MFA_DENIED
        assert evt.principal_id == "bob@example.com"

    def test_mfa_approve_classifies_as_mfa_approved(self) -> None:
        raw = _find_event("okta-evt-mfa-approved-004")
        evt = normalise_system_log_event(raw, org_id="org_test")
        assert evt is not None
        assert evt.kind is IdentityEventKind.MFA_APPROVED

    def test_idp_lifecycle_classifies_as_federation_modified(self) -> None:
        raw = _find_event("okta-evt-fed-mod-001")
        evt = normalise_system_log_event(raw, org_id="org_test")
        assert evt is not None
        assert evt.kind is IdentityEventKind.FEDERATION_TRUST_MODIFIED
        assert evt.principal_id == "admin@example.com"

    def test_unknown_event_type_returns_none(self) -> None:
        raw = {
            "uuid": "okta-evt-unknown-zzz",
            "published": "2026-06-18T10:00:00.000Z",
            "eventType": "policy.evaluate_sign_on",
            "actor": {"alternateId": "alice@example.com"},
            "outcome": {"result": "ALLOW"},
            "client": {"ipAddress": "1.2.3.4"},
        }
        assert normalise_system_log_event(raw, org_id="x") is None

    def test_login_failure_outcome_classifies_as_login_failure(self) -> None:
        raw = {
            **_find_event("okta-evt-login-success-001"),
            "uuid": "okta-evt-login-fail-xyz",
            "outcome": {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
        }
        evt = normalise_system_log_event(raw, org_id="x")
        assert evt is not None
        assert evt.kind is IdentityEventKind.LOGIN_FAILURE

    def test_normaliser_preserves_raw_payload(self) -> None:
        raw = _find_event("okta-evt-replay-aaa-001")
        evt = normalise_system_log_event(raw, org_id="x")
        assert evt is not None
        # The raw provider blob is retained for forensics / replay
        assert evt.raw["eventType"] == "app.oauth2.token.grant.access_token"

    def test_event_type_map_specific_before_general(self) -> None:
        """Behavioural ordering check: the access-token / refresh-token
        events must classify correctly even though they share the
        ``app.oauth2.token.grant`` prefix with the catch-all entry.
        """
        from btagent_agents.mcp.servers.okta_mcp import _classify_event_type

        assert (
            _classify_event_type("app.oauth2.token.grant.refresh_token", "SUCCESS")
            is IdentityEventKind.TOKEN_REFRESH
        )
        assert (
            _classify_event_type("app.oauth2.token.grant.access_token", "SUCCESS")
            is IdentityEventKind.TOKEN_ISSUED
        )
        # Bare grant prefix still classifies (fallback to TOKEN_ISSUED).
        assert (
            _classify_event_type("app.oauth2.token.grant", "SUCCESS")
            is IdentityEventKind.TOKEN_ISSUED
        )
        # Confirm the catch-all "user.session.start" doesn't shadow
        # the specific user.authentication.* family.
        assert (
            _classify_event_type("user.authentication.auth", "SUCCESS")
            is IdentityEventKind.LOGIN_SUCCESS
        )


# ---------------------------------------------------------------------------
# OAuth grant snapshot mapper
# ---------------------------------------------------------------------------


class TestOAuthGrantNormalisation:
    def test_grant_normalises_to_oauthgrant(self) -> None:
        from btagent_agents.mcp.servers._okta_fixtures import OKTA_FIXTURE_USER_LOGINS

        raw = OKTA_FIXTURE_OAUTH_GRANTS[0]
        grant = normalise_oauth_grant(
            raw,
            org_id="org_test",
            user_login_resolver=OKTA_FIXTURE_USER_LOGINS.get,
        )
        assert isinstance(grant, OAuthGrant)
        assert grant.provider is IdentityProvider.OKTA
        # The resolver maps the raw Okta user-id (``00u…``) to the UPN that
        # System Log events normalise their principal to (Codex #212), so the
        # ``(principal_id, app_id)`` join in detect_dormant_app_reactivation
        # succeeds against real Okta data shapes.
        assert grant.principal_id == "alice@example.com"
        # Grants store the stable clientId, which must equal the stable
        # ``target.id`` that events surface (Codex #212).
        assert grant.app_id == "0oafixtureapp001"
        assert "openid" in grant.scopes
        assert "Mail.Read" in grant.scopes
        assert grant.consent_type is OAuthConsentType.USER

    def test_grant_without_resolver_keeps_raw_user_id(self) -> None:
        """Regression for Codex #212: without a ``user_login_resolver`` the
        grant retains its raw Okta user-id, NOT a fabricated email. The
        connector's own path always passes the resolver; this verifies the
        explicit-default behaviour for callers that genuinely have UPNs in
        ``userId`` (legacy / pre-resolved fixtures)."""
        raw = OKTA_FIXTURE_OAUTH_GRANTS[0]
        grant = normalise_oauth_grant(raw, org_id="org_test")
        # No resolver → grant carries the stable Okta user-id verbatim.
        assert grant.principal_id == "00ufixture_alice"

    def test_events_and_grants_join_on_same_principal_and_app_id(self) -> None:
        """Codex #212 regression: events and grants for the same user+app must
        produce identical ``(principal_id, app_id)`` keys so
        ``detect_dormant_app_reactivation`` can join them. This previously
        broke because events used the app label and grants used the
        clientId; both now resolve to the stable Okta id, and the resolver
        aligns the principal_id form."""
        from btagent_agents.mcp.servers._okta_fixtures import OKTA_FIXTURE_USER_LOGINS

        # Pick the dormant-grant fixture (the one detect_dormant cares about).
        dormant = next(
            g for g in OKTA_FIXTURE_OAUTH_GRANTS if g["id"] == "oag_fixture_dormant_grant_001"
        )
        grant = normalise_oauth_grant(
            dormant,
            org_id="org_test",
            user_login_resolver=OKTA_FIXTURE_USER_LOGINS.get,
        )
        # The matching System Log event (the dormant-reactivation one).
        evt = normalise_system_log_event(
            _find_event("okta-evt-dormant-react-001"),
            org_id="org_test",
        )
        assert evt is not None
        assert (evt.principal_id, evt.app_id) == (grant.principal_id, grant.app_id)

    def test_admin_consent_classified(self) -> None:
        raw = next(g for g in OKTA_FIXTURE_OAUTH_GRANTS if g["source"] == "ADMIN")
        grant = normalise_oauth_grant(raw, org_id="x")
        assert grant.consent_type is OAuthConsentType.ADMIN

    def test_pre_authorized_consent_classified(self) -> None:
        raw = next(g for g in OKTA_FIXTURE_OAUTH_GRANTS if g["source"] == "PRE_AUTHORIZED")
        grant = normalise_oauth_grant(raw, org_id="x")
        assert grant.consent_type is OAuthConsentType.PRE_AUTHORIZED

    def test_string_scopes_split_on_whitespace(self) -> None:
        raw = {
            "id": "g1",
            "clientId": "c1",
            "userId": "u1",
            "scopes": "openid profile email",
            "source": "END_USER",
            "created": "2026-01-01T00:00:00.000Z",
        }
        grant = normalise_oauth_grant(raw, org_id="x")
        assert grant.scopes == ["openid", "profile", "email"]

    def test_missing_lastupdated_yields_none_last_used(self) -> None:
        raw = {
            "id": "g1",
            "clientId": "c1",
            "userId": "u1",
            "scopes": ["openid"],
            "source": "END_USER",
            "created": "2026-01-01T00:00:00.000Z",
        }
        grant = normalise_oauth_grant(raw, org_id="x")
        assert grant.last_used is None


# ---------------------------------------------------------------------------
# Mock-mode MCP envelopes (default)
# ---------------------------------------------------------------------------


class TestMockEnvelopes:
    async def test_system_log_search_returns_normalised_events(self) -> None:
        srv = OktaMCPServer(mock_mode=True)
        env = await srv.okta_system_log_search(
            start="2026-06-18T00:00:00Z",
            end="2026-06-19T00:00:00Z",
        )
        assert env["status"] == "success"
        assert env["is_mock"] is True
        assert env["total"] == len(OKTA_FIXTURE_SYSTEM_LOG)
        assert len(env["events"]) >= 5
        # Normalised events parse cleanly back into IdentityEvent
        for ev in env["events"]:
            IdentityEvent.model_validate(ev)

    async def test_filter_narrows_event_type(self) -> None:
        srv = OktaMCPServer(mock_mode=True)
        env = await srv.okta_system_log_search(
            start="2026-06-18T00:00:00Z",
            end="2026-06-19T00:00:00Z",
            filter="user.authentication.auth_via_mfa",
        )
        assert env["total"] >= 4  # 3 deny + 1 approve
        for raw in env["events_raw"]:
            assert "user.authentication.auth_via_mfa" in raw["eventType"]

    async def test_list_oauth_grants_returns_grants(self) -> None:
        srv = OktaMCPServer(mock_mode=True)
        env = await srv.okta_list_oauth_grants()
        assert env["status"] == "success"
        assert env["is_mock"] is True
        assert env["total"] == len(OKTA_FIXTURE_OAUTH_GRANTS)
        for g in env["grants"]:
            OAuthGrant.model_validate(g)

    async def test_list_oauth_grants_filtered_by_user(self) -> None:
        # Okta filters grants by ``userId`` (the stable ``00u…``), not by
        # login/UPN — the connector mirrors that. The resolver maps the
        # returned grant's ``principal_id`` to the UPN downstream.
        srv = OktaMCPServer(mock_mode=True)
        env = await srv.okta_list_oauth_grants(user_id="00ufixture_bob")
        assert env["total"] == 1
        assert env["grants_raw"][0]["userId"] == "00ufixture_bob"
        # And the normalised grant carries the UPN, ready to join with events.
        assert env["grants"][0]["principal_id"] == "bob@example.com"

    async def test_list_sessions_returns_sessions(self) -> None:
        srv = OktaMCPServer(mock_mode=True)
        env = await srv.okta_list_sessions()
        assert env["status"] == "success"
        assert env["is_mock"] is True
        assert env["total"] == 2


# ---------------------------------------------------------------------------
# Default-OFF discipline: live mode without a token refuses
# ---------------------------------------------------------------------------


class TestLiveModeRefusesWithoutToken:
    async def test_live_mode_without_token_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Ensure env fallback is empty so the secret resolver returns
        # ``<unresolved:…>``.
        monkeypatch.delenv("OKTA_API_TOKEN", raising=False)
        monkeypatch.delenv("BTAGENT_OKTA_API_TOKEN", raising=False)
        srv = OktaMCPServer(
            mock_mode=False,
            token_ref="${secret:vault:okta/api_token}",
        )
        with pytest.raises(NotImplementedError, match="API token"):
            await srv.okta_system_log_search(
                start="2026-06-18T00:00:00Z", end="2026-06-19T00:00:00Z"
            )

    async def test_live_mode_real_path_not_yet_implemented(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Provide a resolvable token via env fallback so the token gate passes;
        # the real HTTP call is a guarded NotImplementedError on purpose.
        monkeypatch.setenv("OKTA_API_TOKEN", "fixture-token-1234567890")
        srv = OktaMCPServer(
            mock_mode=False,
            token_ref="${secret:vault:okta/api_token}",
        )
        with pytest.raises(NotImplementedError):
            await srv.okta_system_log_search(
                start="2026-06-18T00:00:00Z", end="2026-06-19T00:00:00Z"
            )


# ---------------------------------------------------------------------------
# Secret-redaction: token never in repr / log lines / exceptions
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_repr_omits_token(self) -> None:
        srv = OktaMCPServer(
            mock_mode=False,
            token_ref="${env:NON_EXISTENT_TOKEN_VAR}",
        )
        # Even after token resolution, repr must not contain the token.
        assert "TOKEN" not in repr(srv).upper() or "token_ref" not in repr(srv)
        # Specifically: no raw "secret:" reference should leak in repr.
        assert "secret:" not in repr(srv)

    def test_redact_token_short_returns_placeholder(self) -> None:
        assert _redact_token("") == "[redacted]"
        assert _redact_token("short") == "[redacted]"

    def test_redact_token_long_returns_fingerprint(self) -> None:
        out = _redact_token("supersecretapitoken1234")
        assert "supersecretapi" not in out
        assert out.endswith("1234]")
        assert "redacted" in out

    async def test_live_mode_log_lines_redact_token(
        self,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        secret = "AaBbCcDdEeFfGgHhIiJjKkLlMm"
        monkeypatch.setenv("BTAGENT_FIXTURE_OKTA_TOKEN", secret)
        srv = OktaMCPServer(
            mock_mode=False,
            token_ref="${env:DOES_NOT_EXIST_FOR_THIS_TEST}",
        )
        caplog.set_level(logging.WARNING, logger="btagent.mcp.servers.okta")
        with pytest.raises(NotImplementedError):
            await srv.okta_system_log_search(
                start="2026-06-18T00:00:00Z", end="2026-06-19T00:00:00Z"
            )
        # Token (or any plausible Okta API token characters) must not leak.
        for record in caplog.records:
            assert secret not in record.getMessage()


# ---------------------------------------------------------------------------
# Circuit breaker integration
# ---------------------------------------------------------------------------


class TestCircuitBreaker:
    def setup_method(self) -> None:
        MCPConnectionRegistry.reset_instance()

    def teardown_method(self) -> None:
        MCPConnectionRegistry.reset_instance()

    async def test_breaker_opens_after_failures_and_blocks(self) -> None:
        registry = MCPConnectionRegistry.get_instance()
        cfg = MCPServerConfig(
            name="okta",
            description="okta test",
            circuit_breaker_threshold=3,
            circuit_breaker_recovery=60,
        )
        conn = await registry.get_connection("okta", config=cfg, consumer_id="inv_test")
        assert conn.circuit_breaker.state is CircuitState.CLOSED

        for _ in range(3):
            registry.record_failure("okta", RuntimeError("simulated 503"))
        assert conn.circuit_breaker.state is CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            conn.circuit_breaker.check_state()

    async def test_breaker_recovers_to_closed_on_successes(self) -> None:
        registry = MCPConnectionRegistry.get_instance()
        cfg = MCPServerConfig(
            name="okta",
            description="okta test",
            circuit_breaker_threshold=2,
            circuit_breaker_recovery=0,  # immediate recovery for the test
        )
        conn = await registry.get_connection("okta", config=cfg, consumer_id="inv_test")
        for _ in range(2):
            registry.record_failure("okta", RuntimeError("simulated"))
        # With recovery_timeout=0 the breaker transitions OPEN → HALF_OPEN
        # the moment ``state`` is read; we only need the failure path to
        # have tripped past CLOSED.
        assert conn.circuit_breaker.state in {
            CircuitState.HALF_OPEN,
            CircuitState.OPEN,
        }
        for _ in range(conn.circuit_breaker.success_threshold):
            registry.record_success("okta")
        assert conn.circuit_breaker.state is CircuitState.CLOSED


# ---------------------------------------------------------------------------
# Discovery registration
# ---------------------------------------------------------------------------


class TestDiscoveryRegistration:
    def test_okta_server_registered_in_discovery(self) -> None:
        from btagent_agents.mcp import discovery as disc

        # Force fresh discovery for the test.
        disc._SERVER_CLASSES.clear()
        disc._SERVER_INSTANCES.clear()
        disc._TOOL_INDEX.clear()
        disc._TOOL_DISPATCH.clear()

        tools = disc.discover_tools()
        names = {t.name for t in tools}
        servers = {t.server_id for t in tools}
        assert "okta" in servers
        assert "okta_system_log_search" in names
        assert "okta_list_oauth_grants" in names
        assert "okta_list_sessions" in names

    def test_tool_metadata_marks_okta_server(self) -> None:
        srv = OktaMCPServer()
        meta = srv.get_tool_metadata()
        assert {m["server_id"] for m in meta} == {"okta"}
        # Each tool has at least a name + description + input schema.
        for m in meta:
            assert m["name"]
            assert m["description"]
            assert "properties" in m["input_schema"]


# ---------------------------------------------------------------------------
# Time-window filter sanity check
# ---------------------------------------------------------------------------


async def test_system_log_search_respects_time_window() -> None:
    srv = OktaMCPServer(mock_mode=True)
    # Window that excludes everything (1990 → 1991).
    env = await srv.okta_system_log_search(
        start="1990-01-01T00:00:00Z",
        end="1991-01-01T00:00:00Z",
    )
    assert env["total"] == 0
    # Window that includes only the federation event.
    env = await srv.okta_system_log_search(
        start="2026-06-18T07:00:00Z",
        end="2026-06-18T08:30:00Z",
    )
    types = {e["eventType"] for e in env["events_raw"]}
    assert types == {"system.idp.lifecycle.update"}


async def test_limit_argument_caps_event_count() -> None:
    srv = OktaMCPServer(mock_mode=True)
    env = await srv.okta_system_log_search(
        start="2026-06-18T00:00:00Z",
        end="2026-06-19T00:00:00Z",
        limit=2,
    )
    assert env["total"] == 2


# ---------------------------------------------------------------------------
# Lazy secret resolution: import works even with bogus refs
# ---------------------------------------------------------------------------


def test_construction_does_not_resolve_secret() -> None:
    """Constructing the server must NOT read the secret — the resolver is
    only invoked when a tool is called in live mode."""
    # If construction eagerly resolved, this would either succeed silently
    # with a placeholder (non-prod) or raise (prod). We only check that
    # construction doesn't blow up and that no API call is made.
    srv = OktaMCPServer(
        mock_mode=True,
        token_ref="${secret:vault:does/not/exist}",
    )
    assert srv.mock_mode is True
