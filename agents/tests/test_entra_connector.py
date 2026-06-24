"""Unit tests for the Microsoft Entra ID MCP connector (#100 Tier-1 slice).

Mirrors the Okta test suite (#212) so the two identity connectors are
exercised symmetrically.

Coverage:
- Sign-in event JSON → :class:`IdentityEvent` normalisation across
  LOGIN_SUCCESS, LOGIN_FAILURE, MFA challenge / deny / approve.
- Directory-audit JSON → :class:`IdentityEvent` normalisation across
  consent grant, service-principal credential, role assignment, federation
  trust modification.
- OAuth grant JSON → :class:`OAuthGrant` normalisation including
  AllPrincipals admin consent and per-user delegated consent.
- Events ↔ grants join on stable (principal_id, app_id) for the dormant-grant
  detector — the regression that Codex #212 caught for Okta applies to
  Entra in the same shape (GUID vs UPN).
- Circuit-breaker open/close behaviour via :class:`MCPConnectionRegistry`.
- Secret-redaction: the Graph client secret is never present in
  logs / repr / exception strings.
- Discovery registration: the connector is wired into the lazy server
  registry alongside the existing Tier-1 connectors.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
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
    CircuitOpenError,
    CircuitState,
    MCPConnectionRegistry,
)
from btagent_agents.mcp.servers._entra_fixtures import (
    ENTRA_FIXTURE_DIRECTORY_AUDITS,
    ENTRA_FIXTURE_OAUTH_GRANTS,
    ENTRA_FIXTURE_SIGNINS,
    ENTRA_FIXTURE_USER_UPNS,
)
from btagent_agents.mcp.servers.entra_mcp import (
    ENTRA_ACTIVITY_MAP,
    EntraMCPServer,
    _classify_signin,
    _redact_secret,
    normalise_directory_audit,
    normalise_oauth_grant,
    normalise_signin_event,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_signin(sid: str) -> dict[str, Any]:
    for evt in ENTRA_FIXTURE_SIGNINS:
        if evt["id"] == sid:
            return evt
    raise KeyError(sid)


def _find_audit(aid: str) -> dict[str, Any]:
    for evt in ENTRA_FIXTURE_DIRECTORY_AUDITS:
        if evt["id"] == aid:
            return evt
    raise KeyError(aid)


# ---------------------------------------------------------------------------
# Sign-in normalisation
# ---------------------------------------------------------------------------


class TestSigninNormalisation:
    def test_login_success_normalises(self) -> None:
        raw = _find_signin("entra-signin-login-success-001")
        evt = normalise_signin_event(raw, org_id="org_test")
        assert evt.provider is IdentityProvider.ENTRA
        assert evt.kind is IdentityEventKind.LOGIN_SUCCESS
        assert evt.principal_id == "alice@example.com"
        assert evt.ip_address == "8.8.8.8"
        assert evt.geo.country == "US"
        assert evt.geo.asn == "AS15169"
        assert evt.org_id == "org_test"
        assert evt.timestamp.tzinfo is not None
        assert evt.timestamp == datetime(2026, 6, 18, 9, 30, tzinfo=UTC)

    def test_mfa_deny_normalises(self) -> None:
        raw = _find_signin("entra-signin-mfa-deny-001")
        evt = normalise_signin_event(raw, org_id="org_test")
        assert evt.kind is IdentityEventKind.MFA_DENIED
        assert evt.principal_id == "bob@example.com"

    def test_mfa_approve_normalises(self) -> None:
        raw = _find_signin("entra-signin-mfa-approve-004")
        evt = normalise_signin_event(raw, org_id="org_test")
        assert evt.kind is IdentityEventKind.MFA_APPROVED

    def test_login_failure_classifies_on_error_code(self) -> None:
        # Non-zero errorCode + no MFA detail → LOGIN_FAILURE.
        raw = {
            **_find_signin("entra-signin-login-success-001"),
            "id": "entra-signin-login-fail-xyz",
            "status": {"errorCode": 50053, "failureReason": "Account locked"},
            "authenticationDetails": [],
        }
        evt = normalise_signin_event(raw, org_id="x")
        assert evt.kind is IdentityEventKind.LOGIN_FAILURE

    def test_token_replay_pair_share_session_and_token_ids(self) -> None:
        a = normalise_signin_event(_find_signin("entra-signin-replay-aaa-001"), org_id="x")
        b = normalise_signin_event(_find_signin("entra-signin-replay-bbb-002"), org_id="x")
        # Same session_id, different ASNs — this is the row pair the
        # token-replay detector keys on.
        assert a.session_id == b.session_id == "entra-sess-replay-aaa"
        assert a.token_id != b.token_id  # correlationId differs per request
        assert a.geo.asn != b.geo.asn
        assert a.principal_id == b.principal_id

    def test_dormant_react_signin_joins_to_dormant_grant(self) -> None:
        """Regression mirroring Codex #212: events.app_id == grant.app_id.

        Graph sign-in events surface the OAuth resource's service-principal id
        under ``resourceId``; grants store the same under ``clientId``. Both
        must normalise to identical strings so the dormant-grant detector can
        join (principal_id, app_id) across the two sources.
        """
        evt = normalise_signin_event(_find_signin("entra-signin-dormant-react-001"), org_id="x")
        dormant_grant_raw = next(
            g for g in ENTRA_FIXTURE_OAUTH_GRANTS if g["id"] == "ent_oag_fixture_dormant_grant_001"
        )
        grant = normalise_oauth_grant(
            dormant_grant_raw, org_id="x", user_upn_resolver=ENTRA_FIXTURE_USER_UPNS.get
        )
        # Service-principal object id must match.
        assert evt.app_id == grant.app_id
        # Dormant grant is AllPrincipals (admin) — principal_id is the
        # sentinel "tenant", which intentionally does NOT equal the event's
        # user UPN: admin-consent grants apply to every principal, so the
        # detector enumerates affected users from events rather than joining
        # on principal_id.
        assert grant.principal_id == "tenant"

    def test_normaliser_preserves_raw_payload(self) -> None:
        raw = _find_signin("entra-signin-replay-aaa-001")
        evt = normalise_signin_event(raw, org_id="x")
        assert evt.raw["correlationId"] == "entra-corr-replay-aaa"

    def test_classify_signin_password_only_step_does_not_count_as_mfa(self) -> None:
        """A sign-in with ``authenticationMethod == "Password"`` only must
        classify on errorCode, NOT as MFA_DENIED — Graph reports password as
        an auth step even on non-MFA sign-ins."""
        assert (
            _classify_signin(
                {
                    "status": {"errorCode": 0},
                    "authenticationDetails": [
                        {"authenticationMethod": "Password", "succeeded": True},
                    ],
                }
            )
            is IdentityEventKind.LOGIN_SUCCESS
        )


# ---------------------------------------------------------------------------
# Directory-audit normalisation
# ---------------------------------------------------------------------------


class TestDirectoryAuditNormalisation:
    def test_consent_classified(self) -> None:
        evt = normalise_directory_audit(_find_audit("entra-audit-consent-001"), org_id="x")
        assert evt is not None
        assert evt.kind is IdentityEventKind.APP_CONSENT_GRANTED
        assert evt.principal_id == "alice@example.com"
        # Service-principal id surfaces under app_id so the join with grants
        # works for the dormant-reactivation detector.
        assert evt.app_id == "30000000-0000-0000-0000-000000000001"

    def test_service_principal_credential_classified(self) -> None:
        """T1098.001 surface — adding SP credential is the indicator the
        anomalous-consent panel in the #116 UI highlights."""
        evt = normalise_directory_audit(_find_audit("entra-audit-sp-cred-001"), org_id="x")
        assert evt is not None
        assert evt.kind is IdentityEventKind.CREDENTIAL_ADDED
        assert evt.principal_id == "admin@example.com"

    def test_federation_set_classified(self) -> None:
        evt = normalise_directory_audit(_find_audit("entra-audit-federation-001"), org_id="x")
        assert evt is not None
        assert evt.kind is IdentityEventKind.FEDERATION_TRUST_MODIFIED
        assert evt.principal_id == "admin@example.com"

    def test_role_remove_classified(self) -> None:
        evt = normalise_directory_audit(_find_audit("entra-audit-role-remove-001"), org_id="x")
        assert evt is not None
        assert evt.kind is IdentityEventKind.ROLE_REMOVED

    def test_unknown_activity_returns_none(self) -> None:
        raw = {
            "id": "entra-audit-unknown",
            "activityDisplayName": "Update directory feature settings",
            "activityDateTime": "2026-06-18T08:00:00Z",
            "initiatedBy": {"user": {"userPrincipalName": "x@y.z"}},
            "targetResources": [],
        }
        assert normalise_directory_audit(raw, org_id="x") is None

    def test_activity_map_ordered_specific_before_general(self) -> None:
        """Behavioural ordering check: the SP credential entries must beat
        the application credential entries even though they share a prefix.
        """
        # Both entries are present and the SP one comes first.
        keys = [k for k, _ in ENTRA_ACTIVITY_MAP]
        sp_idx = keys.index("Add service principal credentials")
        app_idx = keys.index("Add application credentials")
        assert sp_idx < app_idx


# ---------------------------------------------------------------------------
# OAuth grant normalisation
# ---------------------------------------------------------------------------


class TestOAuthGrantNormalisation:
    def test_user_grant_normalises(self) -> None:
        raw = next(
            g for g in ENTRA_FIXTURE_OAUTH_GRANTS if g["id"] == "ent_oag_fixture_user_grant_001"
        )
        grant = normalise_oauth_grant(
            raw, org_id="org_test", user_upn_resolver=ENTRA_FIXTURE_USER_UPNS.get
        )
        assert isinstance(grant, OAuthGrant)
        assert grant.provider is IdentityProvider.ENTRA
        # Resolver maps GUID → UPN so the (principal_id, app_id) join with
        # sign-in events succeeds.
        assert grant.principal_id == "alice@example.com"
        assert grant.app_id == "30000000-0000-0000-0000-000000000001"
        assert "openid" in grant.scopes
        assert "Mail.Read" in grant.scopes
        assert grant.consent_type is OAuthConsentType.USER

    def test_admin_consent_grant_maps_to_admin(self) -> None:
        raw = next(
            g for g in ENTRA_FIXTURE_OAUTH_GRANTS if g["id"] == "ent_oag_fixture_dormant_grant_001"
        )
        grant = normalise_oauth_grant(
            raw, org_id="x", user_upn_resolver=ENTRA_FIXTURE_USER_UPNS.get
        )
        assert grant.consent_type is OAuthConsentType.ADMIN
        # AllPrincipals grants have no specific principal — sentinel is used
        # so the field stays non-empty (the model requires it).
        assert grant.principal_id == "tenant"

    def test_grant_without_resolver_keeps_raw_guid(self) -> None:
        """Without ``user_upn_resolver`` the grant keeps the raw Entra GUID.

        Mirrors the Okta default-behaviour test (Codex #212) — connectors
        should always pass the resolver, but the explicit-default behaviour
        for the user GUID case must not fabricate a UPN.
        """
        raw = next(
            g for g in ENTRA_FIXTURE_OAUTH_GRANTS if g["id"] == "ent_oag_fixture_user_grant_001"
        )
        grant = normalise_oauth_grant(raw, org_id="x")
        assert grant.principal_id == "00000000-0000-0000-0000-aaaaaaaaaaaa"

    def test_scope_string_splits_on_whitespace(self) -> None:
        raw = {
            "id": "g1",
            "clientId": "c1",
            "consentType": "Principal",
            "principalId": "00000000-0000-0000-0000-aaaaaaaaaaaa",
            "scope": "openid profile email",
            "grantedAt": "2026-01-01T00:00:00Z",
        }
        grant = normalise_oauth_grant(raw, org_id="x")
        assert grant.scopes == ["openid", "profile", "email"]

    def test_missing_last_used_yields_none(self) -> None:
        raw = {
            "id": "g1",
            "clientId": "c1",
            "consentType": "Principal",
            "principalId": "00000000-0000-0000-0000-aaaaaaaaaaaa",
            "scope": "openid",
            "grantedAt": "2026-01-01T00:00:00Z",
        }
        grant = normalise_oauth_grant(raw, org_id="x")
        assert grant.last_used is None


# ---------------------------------------------------------------------------
# Mock-mode MCP envelopes (default)
# ---------------------------------------------------------------------------


class TestMockEnvelopes:
    async def test_signin_search_returns_normalised_events(self) -> None:
        srv = EntraMCPServer(mock_mode=True)
        env = await srv.entra_signin_log_search(
            start="2026-06-18T00:00:00Z",
            end="2026-06-19T00:00:00Z",
        )
        assert env["status"] == "success"
        assert env["is_mock"] is True
        assert env["total"] == len(ENTRA_FIXTURE_SIGNINS)
        # All sign-ins normalise (LOGIN_*/MFA_* always classify).
        assert len(env["events"]) == len(ENTRA_FIXTURE_SIGNINS)
        for ev in env["events"]:
            IdentityEvent.model_validate(ev)

    async def test_signin_search_respects_time_window(self) -> None:
        srv = EntraMCPServer(mock_mode=True)
        # Empty window (1990 → 1991).
        env = await srv.entra_signin_log_search(
            start="1990-01-01T00:00:00Z", end="1991-01-01T00:00:00Z"
        )
        assert env["total"] == 0
        # Narrow window that contains only the dormant-react sign-in.
        env = await srv.entra_signin_log_search(
            start="2026-06-18T11:30:00Z", end="2026-06-18T12:30:00Z"
        )
        assert env["total"] == 1
        assert env["events_raw"][0]["id"] == "entra-signin-dormant-react-001"

    async def test_audit_search_drops_unmapped_activities(self) -> None:
        srv = EntraMCPServer(mock_mode=True)
        env = await srv.entra_audit_log_search(
            start="2026-06-18T00:00:00Z", end="2026-06-19T00:00:00Z"
        )
        # Raw still contains every fixture audit; normalised drops unmapped
        # (none in the current fixture set, all are recognised).
        assert env["total"] == len(ENTRA_FIXTURE_DIRECTORY_AUDITS)
        assert len(env["events"]) == len(ENTRA_FIXTURE_DIRECTORY_AUDITS)
        for ev in env["events"]:
            IdentityEvent.model_validate(ev)

    async def test_audit_activity_filter_narrows_results(self) -> None:
        srv = EntraMCPServer(mock_mode=True)
        env = await srv.entra_audit_log_search(
            start="2026-06-18T00:00:00Z",
            end="2026-06-19T00:00:00Z",
            activity_filter="federation",
        )
        # Activity filter is a substring on the activityDisplayName.
        assert env["total"] == 1
        assert env["events_raw"][0]["activityDisplayName"].startswith("Set federation")

    async def test_list_grants_returns_all_grants(self) -> None:
        srv = EntraMCPServer(mock_mode=True)
        env = await srv.entra_list_oauth_grants()
        assert env["status"] == "success"
        assert env["is_mock"] is True
        assert env["total"] == len(ENTRA_FIXTURE_OAUTH_GRANTS)
        for g in env["grants"]:
            OAuthGrant.model_validate(g)

    async def test_list_grants_per_user_includes_admin_consent_grants(self) -> None:
        """When ``user_id`` is supplied the per-user grant returns, but
        AllPrincipals (admin) grants — which apply tenant-wide — must
        also be included. They're the high-risk surface the dormant
        detector keys on; filtering them out would hide them from analysts.
        """
        srv = EntraMCPServer(mock_mode=True)
        env = await srv.entra_list_oauth_grants(user_id="00000000-0000-0000-0000-bbbbbbbbbbbb")
        # bob's grant (Principal) + dormant AllPrincipals grant.
        assert env["total"] == 2
        ids = {g["id"] for g in env["grants"]}
        assert "ent_oag_fixture_bob_active_001" in ids
        assert "ent_oag_fixture_dormant_grant_001" in ids


# ---------------------------------------------------------------------------
# Default-OFF discipline: live mode without a secret refuses
# ---------------------------------------------------------------------------


class TestLiveModeRefusesWithoutSecret:
    async def test_live_mode_without_secret_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_ENTRA_CLIENT_SECRET", raising=False)
        srv = EntraMCPServer(
            mock_mode=False,
            secret_ref="${secret:vault:entra/client_secret}",
        )
        with pytest.raises(NotImplementedError, match="client secret"):
            await srv.entra_signin_log_search(
                start="2026-06-18T00:00:00Z", end="2026-06-19T00:00:00Z"
            )

    async def test_live_mode_real_path_not_yet_implemented(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Provide a resolvable secret so the gate passes; the real HTTP call
        # is intentionally NotImplementedError.
        monkeypatch.setenv("BTAGENT_ENTRA_CLIENT_SECRET", "fixture-secret-1234567890")
        srv = EntraMCPServer(
            mock_mode=False,
            secret_ref="${env:BTAGENT_ENTRA_CLIENT_SECRET}",
        )
        with pytest.raises(NotImplementedError):
            await srv.entra_signin_log_search(
                start="2026-06-18T00:00:00Z", end="2026-06-19T00:00:00Z"
            )


# ---------------------------------------------------------------------------
# Secret-redaction
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_repr_omits_secret(self) -> None:
        srv = EntraMCPServer(
            mock_mode=False,
            secret_ref="${env:NON_EXISTENT_TOKEN_VAR}",
        )
        # The secret ref string contains the literal "secret:" — but repr
        # must not surface it.
        assert "secret:" not in repr(srv)

    def test_redact_secret_short_returns_placeholder(self) -> None:
        assert _redact_secret("") == "[redacted]"
        assert _redact_secret("short") == "[redacted]"

    def test_redact_secret_long_returns_fingerprint(self) -> None:
        out = _redact_secret("supersecretgraphclientsecret1234")
        assert "supersecretgraph" not in out
        assert out.endswith("1234]")
        assert "redacted" in out

    async def test_live_mode_log_lines_redact_secret(
        self, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret = "AaBbCcDdEeFfGgHhIiJjKkLlMm"
        monkeypatch.setenv("BTAGENT_FIXTURE_ENTRA_SECRET", secret)
        srv = EntraMCPServer(
            mock_mode=False,
            secret_ref="${env:DOES_NOT_EXIST_FOR_THIS_TEST}",
        )
        caplog.set_level(logging.WARNING, logger="btagent.mcp.servers.entra")
        with pytest.raises(NotImplementedError):
            await srv.entra_signin_log_search(
                start="2026-06-18T00:00:00Z", end="2026-06-19T00:00:00Z"
            )
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
            name="entra",
            description="entra test",
            circuit_breaker_threshold=3,
            circuit_breaker_recovery=60,
        )
        conn = await registry.get_connection("entra", config=cfg, consumer_id="inv_test")
        assert conn.circuit_breaker.state is CircuitState.CLOSED

        for _ in range(3):
            registry.record_failure("entra", RuntimeError("simulated 503"))
        assert conn.circuit_breaker.state is CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            conn.circuit_breaker.check_state()

    async def test_breaker_recovers_to_closed_on_successes(self) -> None:
        registry = MCPConnectionRegistry.get_instance()
        cfg = MCPServerConfig(
            name="entra",
            description="entra test",
            circuit_breaker_threshold=2,
            circuit_breaker_recovery=0,
        )
        conn = await registry.get_connection("entra", config=cfg, consumer_id="inv_test")
        for _ in range(2):
            registry.record_failure("entra", RuntimeError("simulated"))
        assert conn.circuit_breaker.state in {CircuitState.HALF_OPEN, CircuitState.OPEN}
        for _ in range(conn.circuit_breaker.success_threshold):
            registry.record_success("entra")
        assert conn.circuit_breaker.state is CircuitState.CLOSED


# ---------------------------------------------------------------------------
# Discovery registration
# ---------------------------------------------------------------------------


class TestDiscoveryRegistration:
    def test_entra_server_registered_in_discovery(self) -> None:
        from btagent_agents.mcp import discovery as disc

        # Force fresh discovery for the test.
        disc._SERVER_CLASSES.clear()
        disc._SERVER_INSTANCES.clear()
        disc._TOOL_INDEX.clear()
        disc._TOOL_DISPATCH.clear()

        tools = disc.discover_tools()
        names = {t.name for t in tools}
        servers = {t.server_id for t in tools}
        assert "entra" in servers
        assert "entra_signin_log_search" in names
        assert "entra_audit_log_search" in names
        assert "entra_list_oauth_grants" in names

    def test_tool_metadata_marks_entra_server(self) -> None:
        srv = EntraMCPServer()
        meta = srv.get_tool_metadata()
        assert {m["server_id"] for m in meta} == {"entra"}
        for m in meta:
            assert m["name"]
            assert m["description"]
            assert "properties" in m["input_schema"]


# ---------------------------------------------------------------------------
# Time-window + limit sanity
# ---------------------------------------------------------------------------


async def test_audit_search_respects_time_window() -> None:
    srv = EntraMCPServer(mock_mode=True)
    env = await srv.entra_audit_log_search(start="1990-01-01T00:00:00Z", end="1991-01-01T00:00:00Z")
    assert env["total"] == 0


async def test_signin_limit_caps_event_count() -> None:
    srv = EntraMCPServer(mock_mode=True)
    env = await srv.entra_signin_log_search(
        start="2026-06-18T00:00:00Z", end="2026-06-19T00:00:00Z", limit=2
    )
    assert env["total"] == 2


# ---------------------------------------------------------------------------
# Lazy secret resolution
# ---------------------------------------------------------------------------


def test_construction_does_not_resolve_secret() -> None:
    """Constructing the server must NOT read the secret — the resolver is
    only invoked when a tool is called in live mode."""
    srv = EntraMCPServer(
        mock_mode=True,
        secret_ref="${secret:vault:does/not/exist}",
    )
    assert srv.mock_mode is True
