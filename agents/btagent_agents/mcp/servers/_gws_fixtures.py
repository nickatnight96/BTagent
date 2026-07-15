"""Recorded Google Workspace Admin SDK fixtures (login + admin/token activity + tokens).

Realistic, anonymised payloads mirroring the field shapes returned by the
Google Workspace Admin SDK for the three surfaces the GWS MCP connector wraps:

- ``GET /admin/reports/v1/activity/users/all/applications/login``
- ``GET /admin/reports/v1/activity/users/all/applications/{admin,token}``
- ``GET /admin/directory/v1/users/{userKey}/tokens``

The set is deliberately small and scenario-driven, matching the Okta / Entra
fixtures' shape so the same #116 detectors exercise all three providers
symmetrically:

1. Three failed 2SV (login_verification) events followed by one success for
   the same principal inside 10 minutes → exercises the MFA-fatigue detector.
2. One plain LOGIN_SUCCESS and one LOGIN_FAILURE (sanity normalisation).
3. One dormant OAuth token (last used ~120 days ago) paired with a fresh
   ``token`` authorize event for the same (principal, client) → exercises the
   dormant-app reactivation detector.
4. Admin events: role assignment, domain-wide delegation grant
   (``AUTHORIZE_API_CLIENT_ACCESS``), SSO toggle (federation-trust change),
   and a password change (credential added).

Timestamp note: the Directory ``tokens`` endpoint returns **no timestamps**
(only clientId / displayText / scopes / anonymous / nativeApp). The
``grantedAt`` / ``lastUsedAt`` keys on the token fixtures are *recorded
enrichment* — the values a live collector derives by correlating each token
with its ``token`` application authorize/request activity events. The
connector's normaliser reads them when present and falls back to epoch.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Fixed identities
# ---------------------------------------------------------------------------

_FIXTURE_PRINCIPAL_ALICE = "alice@example.com"
_FIXTURE_PRINCIPAL_BOB = "bob@example.com"
_FIXTURE_PRINCIPAL_ADMIN = "admin@example.com"

# Google profile ids (numeric strings). Reports events expose the actor as
# ``actor.email`` + ``actor.profileId``; Directory tokens are fetched per
# ``userKey`` and the connector stamps the resolved email so events and
# grants share the same UPN-style ``principal_id`` join key (mirrors the
# Codex #212 GUID→UPN resolver discipline from Okta/Entra).
_FIXTURE_PROFILE_ID_ALICE = "101000000000000000001"
_FIXTURE_PROFILE_ID_BOB = "101000000000000000002"
_FIXTURE_PROFILE_ID_ADMIN = "101000000000000000009"

GWS_FIXTURE_USER_EMAILS: dict[str, str] = {
    _FIXTURE_PROFILE_ID_ALICE: _FIXTURE_PRINCIPAL_ALICE,
    _FIXTURE_PROFILE_ID_BOB: _FIXTURE_PRINCIPAL_BOB,
    _FIXTURE_PROFILE_ID_ADMIN: _FIXTURE_PRINCIPAL_ADMIN,
}

# OAuth clients.
_FIXTURE_APP_MAILSYNC_CLIENT_ID = "400000000001-mailsync.apps.googleusercontent.com"
_FIXTURE_APP_MAILSYNC_NAME = "MailSync Exporter (Third-Party)"
_FIXTURE_APP_CALENDAR_CLIENT_ID = "400000000002-calbot.apps.googleusercontent.com"
_FIXTURE_APP_CALENDAR_NAME = "CalBot Scheduler"


def _login_event(
    *,
    unique_qualifier: str,
    time: str,
    email: str,
    profile_id: str,
    ip: str,
    name: str,
    parameters: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "kind": "admin#reports#activity",
        "id": {
            "time": time,
            "uniqueQualifier": unique_qualifier,
            "applicationName": "login",
            "customerId": "C0example1",
        },
        "actor": {"callerType": "USER", "email": email, "profileId": profile_id},
        "ipAddress": ip,
        "events": [
            {
                "type": "login",
                "name": name,
                "parameters": parameters or [{"name": "login_type", "value": "google_password"}],
            }
        ],
    }


# ---------------------------------------------------------------------------
# Login activity (applications/login)
# ---------------------------------------------------------------------------

GWS_FIXTURE_LOGIN_EVENTS: list[dict[str, Any]] = [
    # Scenario 1 — MFA fatigue: three failed 2SV verifications then a success
    # for alice within 10 minutes (matches detect_mfa_fatigue's default
    # 3-denials/10-minute window).
    _login_event(
        unique_qualifier="-900000000000000001",
        time="2026-06-01T09:00:10.000Z",
        email=_FIXTURE_PRINCIPAL_ALICE,
        profile_id=_FIXTURE_PROFILE_ID_ALICE,
        ip="203.0.113.10",
        name="login_verification",
        parameters=[
            {"name": "login_challenge_method", "multiValue": ["idv_preregistered_phone"]},
            {"name": "login_challenge_status", "value": "failed"},
        ],
    ),
    _login_event(
        unique_qualifier="-900000000000000002",
        time="2026-06-01T09:02:20.000Z",
        email=_FIXTURE_PRINCIPAL_ALICE,
        profile_id=_FIXTURE_PROFILE_ID_ALICE,
        ip="203.0.113.10",
        name="login_verification",
        parameters=[
            {"name": "login_challenge_method", "multiValue": ["idv_preregistered_phone"]},
            {"name": "login_challenge_status", "value": "failed"},
        ],
    ),
    _login_event(
        unique_qualifier="-900000000000000003",
        time="2026-06-01T09:04:30.000Z",
        email=_FIXTURE_PRINCIPAL_ALICE,
        profile_id=_FIXTURE_PROFILE_ID_ALICE,
        ip="203.0.113.10",
        name="login_verification",
        parameters=[
            {"name": "login_challenge_method", "multiValue": ["idv_preregistered_phone"]},
            {"name": "login_challenge_status", "value": "failed"},
        ],
    ),
    _login_event(
        unique_qualifier="-900000000000000004",
        time="2026-06-01T09:06:40.000Z",
        email=_FIXTURE_PRINCIPAL_ALICE,
        profile_id=_FIXTURE_PROFILE_ID_ALICE,
        ip="203.0.113.10",
        name="login_verification",
        parameters=[
            {"name": "login_challenge_method", "multiValue": ["idv_preregistered_phone"]},
            {"name": "login_challenge_status", "value": "passed"},
        ],
    ),
    # Scenario 2 — plain success + failure for bob.
    _login_event(
        unique_qualifier="-900000000000000005",
        time="2026-06-01T10:00:00.000Z",
        email=_FIXTURE_PRINCIPAL_BOB,
        profile_id=_FIXTURE_PROFILE_ID_BOB,
        ip="198.51.100.20",
        name="login_success",
    ),
    _login_event(
        unique_qualifier="-900000000000000006",
        time="2026-06-01T10:05:00.000Z",
        email=_FIXTURE_PRINCIPAL_BOB,
        profile_id=_FIXTURE_PROFILE_ID_BOB,
        ip="198.51.100.20",
        name="login_failure",
        parameters=[
            {"name": "login_type", "value": "google_password"},
            {"name": "login_failure_type", "value": "login_failure_invalid_password"},
        ],
    ),
]


# ---------------------------------------------------------------------------
# Admin + token activity (applications/admin, applications/token)
# ---------------------------------------------------------------------------

GWS_FIXTURE_AUDIT_EVENTS: list[dict[str, Any]] = [
    # Role assignment (T1098) — admin grants bob a delegated-admin role.
    {
        "kind": "admin#reports#activity",
        "id": {
            "time": "2026-06-01T11:00:00.000Z",
            "uniqueQualifier": "-910000000000000001",
            "applicationName": "admin",
            "customerId": "C0example1",
        },
        "actor": {
            "callerType": "USER",
            "email": _FIXTURE_PRINCIPAL_ADMIN,
            "profileId": _FIXTURE_PROFILE_ID_ADMIN,
        },
        "ipAddress": "192.0.2.9",
        "events": [
            {
                "type": "DELEGATED_ADMIN_SETTINGS",
                "name": "ASSIGN_ROLE",
                "parameters": [
                    {"name": "ROLE_NAME", "value": "_HELP_DESK_ADMIN_ROLE"},
                    {"name": "USER_EMAIL", "value": _FIXTURE_PRINCIPAL_BOB},
                ],
            }
        ],
    },
    # Domain-wide delegation grant (high-risk consent surface).
    {
        "kind": "admin#reports#activity",
        "id": {
            "time": "2026-06-01T11:10:00.000Z",
            "uniqueQualifier": "-910000000000000002",
            "applicationName": "admin",
            "customerId": "C0example1",
        },
        "actor": {
            "callerType": "USER",
            "email": _FIXTURE_PRINCIPAL_ADMIN,
            "profileId": _FIXTURE_PROFILE_ID_ADMIN,
        },
        "ipAddress": "192.0.2.9",
        "events": [
            {
                "type": "DOMAIN_SETTINGS",
                "name": "AUTHORIZE_API_CLIENT_ACCESS",
                "parameters": [
                    {"name": "API_CLIENT_NAME", "value": _FIXTURE_APP_MAILSYNC_CLIENT_ID},
                    {
                        "name": "API_SCOPES",
                        "multiValue": ["https://mail.google.com/"],
                    },
                ],
            }
        ],
    },
    # SSO settings toggled (Golden-SAML-adjacent federation change, T1484.002).
    {
        "kind": "admin#reports#activity",
        "id": {
            "time": "2026-06-01T11:20:00.000Z",
            "uniqueQualifier": "-910000000000000003",
            "applicationName": "admin",
            "customerId": "C0example1",
        },
        "actor": {
            "callerType": "USER",
            "email": _FIXTURE_PRINCIPAL_ADMIN,
            "profileId": _FIXTURE_PROFILE_ID_ADMIN,
        },
        "ipAddress": "192.0.2.9",
        "events": [
            {
                "type": "SECURITY_SETTINGS",
                "name": "TOGGLE_SSO_ENABLED",
                "parameters": [{"name": "NEW_VALUE", "value": "true"}],
            }
        ],
    },
    # Password change (credential lifecycle).
    {
        "kind": "admin#reports#activity",
        "id": {
            "time": "2026-06-01T11:30:00.000Z",
            "uniqueQualifier": "-910000000000000004",
            "applicationName": "admin",
            "customerId": "C0example1",
        },
        "actor": {
            "callerType": "USER",
            "email": _FIXTURE_PRINCIPAL_ADMIN,
            "profileId": _FIXTURE_PROFILE_ID_ADMIN,
        },
        "ipAddress": "192.0.2.9",
        "events": [
            {
                "type": "USER_SETTINGS",
                "name": "CHANGE_PASSWORD",
                "parameters": [{"name": "USER_EMAIL", "value": _FIXTURE_PRINCIPAL_BOB}],
            }
        ],
    },
    # Scenario 3 (half 1) — fresh token authorize for alice on the DORMANT
    # MailSync client → the reactivation event the dormant-grant detector
    # joins on (principal_id, app_id).
    {
        "kind": "admin#reports#activity",
        "id": {
            "time": "2026-06-01T12:00:00.000Z",
            "uniqueQualifier": "-910000000000000005",
            "applicationName": "token",
            "customerId": "C0example1",
        },
        "actor": {
            "callerType": "USER",
            "email": _FIXTURE_PRINCIPAL_ALICE,
            "profileId": _FIXTURE_PROFILE_ID_ALICE,
        },
        "ipAddress": "203.0.113.10",
        "events": [
            {
                "type": "auth",
                "name": "authorize",
                "parameters": [
                    {"name": "client_id", "value": _FIXTURE_APP_MAILSYNC_CLIENT_ID},
                    {"name": "app_name", "value": _FIXTURE_APP_MAILSYNC_NAME},
                    {
                        "name": "scope",
                        "multiValue": ["https://mail.google.com/", "openid"],
                    },
                ],
            }
        ],
    },
    # Token revoke for bob's CalBot (grant-revoked lifecycle).
    {
        "kind": "admin#reports#activity",
        "id": {
            "time": "2026-06-01T12:10:00.000Z",
            "uniqueQualifier": "-910000000000000006",
            "applicationName": "token",
            "customerId": "C0example1",
        },
        "actor": {
            "callerType": "USER",
            "email": _FIXTURE_PRINCIPAL_BOB,
            "profileId": _FIXTURE_PROFILE_ID_BOB,
        },
        "ipAddress": "198.51.100.20",
        "events": [
            {
                "type": "auth",
                "name": "revoke",
                "parameters": [
                    {"name": "client_id", "value": _FIXTURE_APP_CALENDAR_CLIENT_ID},
                    {"name": "app_name", "value": _FIXTURE_APP_CALENDAR_NAME},
                ],
            }
        ],
    },
    # An activity the map doesn't know — must be dropped by the normaliser.
    {
        "kind": "admin#reports#activity",
        "id": {
            "time": "2026-06-01T12:20:00.000Z",
            "uniqueQualifier": "-910000000000000007",
            "applicationName": "admin",
            "customerId": "C0example1",
        },
        "actor": {
            "callerType": "USER",
            "email": _FIXTURE_PRINCIPAL_ADMIN,
            "profileId": _FIXTURE_PROFILE_ID_ADMIN,
        },
        "ipAddress": "192.0.2.9",
        "events": [
            {
                "type": "CALENDAR_SETTINGS",
                "name": "CHANGE_CALENDAR_SETTING",
                "parameters": [{"name": "SETTING_NAME", "value": "SHARING_OUTSIDE_DOMAIN"}],
            }
        ],
    },
]


# ---------------------------------------------------------------------------
# Directory tokens (per-user OAuth grants)
# ---------------------------------------------------------------------------
# ``userEmail`` is stamped by the collector (the Directory API is queried per
# userKey); ``grantedAt`` / ``lastUsedAt`` are recorded enrichment derived from
# token activity events (see module docstring).

GWS_FIXTURE_TOKENS: list[dict[str, Any]] = [
    # Scenario 3 (half 2) — alice's DORMANT MailSync grant: last used ~120
    # days before the fixture activity window (2026-06-01).
    {
        "kind": "admin#directory#token",
        "clientId": _FIXTURE_APP_MAILSYNC_CLIENT_ID,
        "displayText": _FIXTURE_APP_MAILSYNC_NAME,
        "scopes": ["https://mail.google.com/", "openid"],
        "anonymous": False,
        "nativeApp": False,
        "userKey": _FIXTURE_PROFILE_ID_ALICE,
        "userEmail": _FIXTURE_PRINCIPAL_ALICE,
        "grantedAt": "2025-09-01T08:00:00.000Z",
        "lastUsedAt": "2026-02-01T08:00:00.000Z",
    },
    # bob's active CalBot grant (used yesterday relative to the window).
    {
        "kind": "admin#directory#token",
        "clientId": _FIXTURE_APP_CALENDAR_CLIENT_ID,
        "displayText": _FIXTURE_APP_CALENDAR_NAME,
        "scopes": ["https://www.googleapis.com/auth/calendar"],
        "anonymous": False,
        "nativeApp": False,
        "userKey": _FIXTURE_PROFILE_ID_BOB,
        "userEmail": _FIXTURE_PRINCIPAL_BOB,
        "grantedAt": "2026-05-01T08:00:00.000Z",
        "lastUsedAt": "2026-05-31T08:00:00.000Z",
    },
    # An anonymous (unverified) app grant — the over-privilege surface the
    # grant-to-unverified-app hunt pack targets. No usage enrichment recorded.
    {
        "kind": "admin#directory#token",
        "clientId": "400000000003-unverified.apps.googleusercontent.com",
        "displayText": "Unverified Drive Utility",
        "scopes": ["https://www.googleapis.com/auth/drive"],
        "anonymous": True,
        "nativeApp": False,
        "userKey": _FIXTURE_PROFILE_ID_ALICE,
        "userEmail": _FIXTURE_PRINCIPAL_ALICE,
        "grantedAt": "2026-05-20T08:00:00.000Z",
    },
]
