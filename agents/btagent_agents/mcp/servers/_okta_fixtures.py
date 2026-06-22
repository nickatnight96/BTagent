"""Recorded Okta System Log + OAuth-grant + session fixtures.

These are realistic, anonymised payloads that mirror the field shapes returned
by Okta's REST API. They live next to the connector (not in ``tests/``) so
the mock-mode code path is fully self-contained and the connector can be
exercised from any test or smoke-runner without a fixtures path arg.

Sources mimicked:
- ``GET /api/v1/logs?since=…&until=…&filter=…``  (System Log)
- ``GET /api/v1/oauth2/<as>/grants``             (OAuth grants)
- ``GET /api/v1/sessions/me`` / per-user             (active sessions)

The set is deliberately small and scenario-driven:
1. Two TOKEN_ISSUED events for the same session from two different ASNs
   → exercises the OAuth token-replay detector (#116).
2. Three MFA_DENIED events followed by one MFA_APPROVED for the same
   principal → exercises the MFA-fatigue detector.
3. One LOGIN_SUCCESS event (sanity normalisation).
4. One FEDERATION_TRUST_MODIFIED (system.idp.lifecycle.update) event.
5. One dormant OAuth grant (last_used > 90 days ago) paired with a
   reactivation event.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# System Log fixtures
# ---------------------------------------------------------------------------

_FIXTURE_PRINCIPAL_ALICE = "alice@example.com"
_FIXTURE_PRINCIPAL_BOB = "bob@example.com"
# Okta-assigned user ids (the form ``userId`` actually takes on live grants /
# sessions). The connector resolves these to the login form events normalise
# on (UPN) via :data:`OKTA_FIXTURE_USER_LOGINS`. Tests use that mapping as the
# ``user_login_resolver`` they pass into :func:`normalise_oauth_grant`.
_FIXTURE_USER_ID_ALICE = "00ufixture_alice"
_FIXTURE_USER_ID_BOB = "00ufixture_bob"
_FIXTURE_TENANT = "https://example.okta.com"

# Stable Okta user-id → login (UPN) lookup. Mirrors what
# ``GET /api/v1/users/{userId}`` would return for ``profile.login`` in live
# integrations.
OKTA_FIXTURE_USER_LOGINS: dict[str, str] = {
    _FIXTURE_USER_ID_ALICE: _FIXTURE_PRINCIPAL_ALICE,
    _FIXTURE_USER_ID_BOB: _FIXTURE_PRINCIPAL_BOB,
}
_FIXTURE_APP_GRAPH = {
    # ``id`` is the stable Okta app id (``0oa…``) — the key the connector +
    # detectors join on. ``alternateId`` is the human label and can differ
    # tenant-to-tenant (Codex #212).
    "id": "0oafixtureapp001",
    "type": "AppInstance",
    "alternateId": "MS Graph OAuth App (Production)",
    "displayName": "MS Graph OAuth App",
}
_FIXTURE_APP_DORMANT = {
    "id": "0oafixtureapp_dormant",
    "type": "AppInstance",
    "alternateId": "Legacy Dormant Addon (Production)",
    "displayName": "Legacy Dormant Addon",
}


def _client_block(ip: str, country: str, city: str, asn: int) -> dict[str, Any]:
    """Build the ``client`` + ``securityContext`` blocks for an event."""
    return {
        "client": {
            "ipAddress": ip,
            "geographicalContext": {
                "country": country,
                "city": city,
                "geolocation": {"lat": 0.0, "lon": 0.0},
            },
            "userAgent": {
                "rawUserAgent": "Mozilla/5.0 (X11; Linux x86_64) BTagentTestUA/1.0",
                "os": "Linux",
                "browser": "FIXTURE",
            },
        },
        "securityContext": {
            "asNumber": asn,
            "asOrg": f"AS{asn} Test Org",
            "isp": "Test ISP",
            "isProxy": False,
        },
    }


def _actor(principal: str) -> dict[str, Any]:
    return {
        "id": f"00ufixture_{principal.split('@')[0]}",
        "type": "User",
        "alternateId": principal,
        "displayName": principal.split("@")[0].title(),
    }


def _outcome(result: str, reason: str = "") -> dict[str, Any]:
    return {"result": result, "reason": reason}


# ---- 1. Token-replay scenario: same session_id from two ASNs --------------
_TOKEN_REPLAY_SESSION = "ext_sess_fixture_replay_001"
_TOKEN_REPLAY_TOKEN = "at_fixture_replay_001"

_EVT_TOKEN_ISSUED_ASN_A: dict[str, Any] = {
    "uuid": "okta-evt-replay-aaa-001",
    "published": "2026-06-18T10:00:00.000Z",
    "eventType": "app.oauth2.token.grant.access_token",
    "displayMessage": "OIDC access token issued",
    "severity": "INFO",
    "actor": _actor(_FIXTURE_PRINCIPAL_ALICE),
    "outcome": _outcome("SUCCESS"),
    "authenticationContext": {
        "authenticationStep": 0,
        "externalSessionId": _TOKEN_REPLAY_SESSION,
        "sessionId": "internal_sess_001",
    },
    "debugContext": {
        "debugData": {
            "dtHash": _TOKEN_REPLAY_TOKEN,
            "requestId": "req_aaa_001",
        },
    },
    "target": [
        _FIXTURE_APP_GRAPH,
        {
            "id": _TOKEN_REPLAY_TOKEN,
            "type": "AccessToken",
            "alternateId": "access-token",
            "displayName": "access-token",
        },
    ],
    **_client_block("8.8.8.8", "US", "Mountain View", 15169),
}

_EVT_TOKEN_ISSUED_ASN_B: dict[str, Any] = {
    "uuid": "okta-evt-replay-bbb-002",
    "published": "2026-06-18T10:18:00.000Z",
    "eventType": "app.oauth2.token.grant.refresh_token",
    "displayMessage": "OIDC refresh token used",
    "severity": "INFO",
    "actor": _actor(_FIXTURE_PRINCIPAL_ALICE),
    "outcome": _outcome("SUCCESS"),
    "authenticationContext": {
        "authenticationStep": 0,
        "externalSessionId": _TOKEN_REPLAY_SESSION,
        "sessionId": "internal_sess_001",
    },
    "debugContext": {
        "debugData": {
            "dtHash": _TOKEN_REPLAY_TOKEN,
            "requestId": "req_bbb_002",
        },
    },
    "target": [
        _FIXTURE_APP_GRAPH,
        {
            "id": _TOKEN_REPLAY_TOKEN,
            "type": "AccessToken",
            "alternateId": "access-token",
            "displayName": "access-token",
        },
    ],
    **_client_block("13.107.4.50", "IE", "Dublin", 8075),
}

# ---- 2. MFA fatigue scenario: 3 denials then approval ---------------------
_MFA_BOB_AUTH_CTX = {
    "authenticationStep": 1,
    "externalSessionId": "ext_sess_mfa_fatigue_bob",
    "sessionId": "internal_sess_mfa_bob",
}

_EVT_MFA_DENIED_1 = {
    "uuid": "okta-evt-mfa-denied-001",
    "published": "2026-06-18T11:00:00.000Z",
    "eventType": "user.authentication.auth_via_mfa",
    "displayMessage": "Authentication of user via MFA",
    "severity": "WARN",
    "actor": _actor(_FIXTURE_PRINCIPAL_BOB),
    "outcome": _outcome("DENY", "USER_REJECTED"),
    "authenticationContext": _MFA_BOB_AUTH_CTX,
    "debugContext": {"debugData": {"factor": "PUSH"}},
    "target": [],
    **_client_block("203.0.113.55", "US", "Reston", 7922),
}
_EVT_MFA_DENIED_2 = {
    **_EVT_MFA_DENIED_1,
    "uuid": "okta-evt-mfa-denied-002",
    "published": "2026-06-18T11:02:00.000Z",
}
_EVT_MFA_DENIED_3 = {
    **_EVT_MFA_DENIED_1,
    "uuid": "okta-evt-mfa-denied-003",
    "published": "2026-06-18T11:04:00.000Z",
}
_EVT_MFA_APPROVED = {
    "uuid": "okta-evt-mfa-approved-004",
    "published": "2026-06-18T11:06:00.000Z",
    "eventType": "user.authentication.auth_via_mfa",
    "displayMessage": "Authentication of user via MFA",
    "severity": "INFO",
    "actor": _actor(_FIXTURE_PRINCIPAL_BOB),
    "outcome": _outcome("SUCCESS"),
    "authenticationContext": _MFA_BOB_AUTH_CTX,
    "debugContext": {"debugData": {"factor": "PUSH"}},
    "target": [],
    **_client_block("203.0.113.55", "US", "Reston", 7922),
}

# ---- 3. Plain LOGIN_SUCCESS event (sanity) --------------------------------
_EVT_LOGIN_SUCCESS = {
    "uuid": "okta-evt-login-success-001",
    "published": "2026-06-18T09:30:00.000Z",
    "eventType": "user.authentication.auth",
    "displayMessage": "User login to Okta",
    "severity": "INFO",
    "actor": _actor(_FIXTURE_PRINCIPAL_ALICE),
    "outcome": _outcome("SUCCESS"),
    "authenticationContext": {
        "authenticationStep": 0,
        "externalSessionId": "ext_sess_login_alice",
        "sessionId": "internal_sess_login_alice",
    },
    "debugContext": {"debugData": {"requestId": "req_login_001"}},
    "target": [],
    **_client_block("8.8.8.8", "US", "Mountain View", 15169),
}

# ---- 4. FEDERATION_TRUST_MODIFIED ----------------------------------------
_EVT_FEDERATION_MOD = {
    "uuid": "okta-evt-fed-mod-001",
    "published": "2026-06-18T08:00:00.000Z",
    "eventType": "system.idp.lifecycle.update",
    "displayMessage": "Identity provider updated",
    "severity": "WARN",
    "actor": _actor("admin@example.com"),
    "outcome": _outcome("SUCCESS"),
    "authenticationContext": {},
    "debugContext": {"debugData": {"idpType": "SAML2"}},
    "target": [
        {
            "id": "0oa_idp_partner_001",
            "type": "IdentityProvider",
            "alternateId": "partner-saml-idp",
            "displayName": "Partner SAML IdP",
        }
    ],
    **_client_block("198.51.100.1", "US", "New York", 7922),
}

# ---- 5. Dormant OAuth grant reactivation event ---------------------------
_EVT_DORMANT_REACTIVATION = {
    "uuid": "okta-evt-dormant-react-001",
    "published": "2026-06-18T12:00:00.000Z",
    "eventType": "app.oauth2.token.grant.access_token",
    "displayMessage": "OIDC access token issued",
    "severity": "INFO",
    "actor": _actor(_FIXTURE_PRINCIPAL_ALICE),
    "outcome": _outcome("SUCCESS"),
    "authenticationContext": {
        "authenticationStep": 0,
        "externalSessionId": "ext_sess_dormant_001",
        "sessionId": "internal_sess_dormant_001",
    },
    "debugContext": {
        "debugData": {
            "dtHash": "at_fixture_dormant_001",
            "requestId": "req_dormant_001",
        }
    },
    "target": [_FIXTURE_APP_DORMANT],
    **_client_block("8.8.8.8", "US", "Mountain View", 15169),
}


# Public fixture lists ------------------------------------------------------
OKTA_FIXTURE_SYSTEM_LOG: list[dict[str, Any]] = [
    _EVT_FEDERATION_MOD,
    _EVT_LOGIN_SUCCESS,
    _EVT_TOKEN_ISSUED_ASN_A,
    _EVT_TOKEN_ISSUED_ASN_B,
    _EVT_MFA_DENIED_1,
    _EVT_MFA_DENIED_2,
    _EVT_MFA_DENIED_3,
    _EVT_MFA_APPROVED,
    _EVT_DORMANT_REACTIVATION,
]

# ---------------------------------------------------------------------------
# OAuth grant fixtures
# ---------------------------------------------------------------------------

OKTA_FIXTURE_OAUTH_GRANTS: list[dict[str, Any]] = [
    {
        "id": "oag_fixture_admin_grant_001",
        "clientId": _FIXTURE_APP_GRAPH["id"],
        "clientName": _FIXTURE_APP_GRAPH["displayName"],
        "clientDisplayName": _FIXTURE_APP_GRAPH["displayName"],
        "userId": _FIXTURE_USER_ID_ALICE,
        "scopes": ["openid", "profile", "offline_access", "Mail.Read"],
        "source": "END_USER",
        "status": "ACTIVE",
        "created": "2026-05-01T09:00:00.000Z",
        "lastUpdated": "2026-06-15T09:00:00.000Z",
    },
    {
        # Dormant grant — last_used was Feb (>90d before the
        # June reactivation event timestamp above).
        "id": "oag_fixture_dormant_grant_001",
        "clientId": _FIXTURE_APP_DORMANT["id"],
        "clientName": _FIXTURE_APP_DORMANT["displayName"],
        "clientDisplayName": _FIXTURE_APP_DORMANT["displayName"],
        "userId": _FIXTURE_USER_ID_ALICE,
        "scopes": ["openid", "profile", "User.Read"],
        "source": "ADMIN",
        "status": "ACTIVE",
        "created": "2025-12-01T09:00:00.000Z",
        "lastUpdated": "2026-02-01T09:00:00.000Z",
    },
    {
        "id": "oag_fixture_bob_active_001",
        "clientId": _FIXTURE_APP_GRAPH["id"],
        "clientName": _FIXTURE_APP_GRAPH["displayName"],
        "clientDisplayName": _FIXTURE_APP_GRAPH["displayName"],
        "userId": _FIXTURE_USER_ID_BOB,
        "scopes": ["openid", "profile"],
        "source": "PRE_AUTHORIZED",
        "status": "ACTIVE",
        "created": "2026-06-10T09:00:00.000Z",
        "lastUpdated": "2026-06-17T09:00:00.000Z",
    },
]


# ---------------------------------------------------------------------------
# Session fixtures
# ---------------------------------------------------------------------------

OKTA_FIXTURE_SESSIONS: list[dict[str, Any]] = [
    {
        "id": "okta_sess_fixture_alice_001",
        "userId": _FIXTURE_USER_ID_ALICE,
        "login": _FIXTURE_PRINCIPAL_ALICE,
        "createdAt": "2026-06-18T09:30:00.000Z",
        "expiresAt": "2026-06-18T21:30:00.000Z",
        "status": "ACTIVE",
        "lastFactorVerification": "2026-06-18T09:30:30.000Z",
        "amr": ["pwd", "mfa"],
        "idp": {"id": "OKTA", "type": "OKTA"},
    },
    {
        "id": "okta_sess_fixture_bob_001",
        "userId": _FIXTURE_USER_ID_BOB,
        "login": _FIXTURE_PRINCIPAL_BOB,
        "createdAt": "2026-06-18T11:06:00.000Z",
        "expiresAt": "2026-06-18T23:06:00.000Z",
        "status": "ACTIVE",
        "lastFactorVerification": "2026-06-18T11:06:00.000Z",
        "amr": ["pwd", "mfa"],
        "idp": {"id": "OKTA", "type": "OKTA"},
    },
]
