"""Recorded Microsoft Entra ID (Azure AD) sign-in + audit + grant fixtures.

These are realistic, anonymised payloads mirroring the field shapes returned by
Microsoft Graph for the three endpoints the Entra MCP connector wraps:

- ``GET /auditLogs/signIns?$filter=createdDateTime ge <start> and lt <end>``
- ``GET /auditLogs/directoryAudits?$filter=activityDateTime ge <start> and lt <end>``
- ``GET /oauth2PermissionGrants`` (delegated) +
  ``GET /servicePrincipals/{id}/appRoleAssignments`` (application)

The set is deliberately small and scenario-driven, matching the Okta fixture's
shape so the same #116 detectors exercise both providers symmetrically:

1. Two sign-in events for the same session id from two different ASNs
   → exercises the OAuth token-replay detector.
2. Three MFA-deny sign-in events followed by one MFA-success for the same
   principal → exercises the MFA-fatigue detector.
3. One plain interactive LOGIN_SUCCESS event (sanity normalisation).
4. One FEDERATION_TRUST_MODIFIED directory audit (``Set federation settings``).
5. One dormant OAuth grant (last used > 90 days ago) paired with a
   reactivation sign-in.
6. One ``Add service principal credential`` directory audit (matches the
   T1098.001 detector in #116).
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Fixed identities
# ---------------------------------------------------------------------------

_FIXTURE_PRINCIPAL_ALICE = "alice@example.com"
_FIXTURE_PRINCIPAL_BOB = "bob@example.com"
_FIXTURE_PRINCIPAL_ADMIN = "admin@example.com"

# Entra (Azure AD) object ids — GUIDs. Live grants reference these in
# ``principalId``; sign-in events expose them under ``userId`` alongside the
# UPN under ``userPrincipalName``. The connector resolves GUID → UPN via the
# fixture map below (mirrors Okta's user-login resolver pattern, Codex #212).
_FIXTURE_USER_ID_ALICE = "00000000-0000-0000-0000-aaaaaaaaaaaa"
_FIXTURE_USER_ID_BOB = "00000000-0000-0000-0000-bbbbbbbbbbbb"
_FIXTURE_USER_ID_ADMIN = "00000000-0000-0000-0000-adadadadadad"

# Stable Entra user-id (GUID) → UPN lookup.
ENTRA_FIXTURE_USER_UPNS: dict[str, str] = {
    _FIXTURE_USER_ID_ALICE: _FIXTURE_PRINCIPAL_ALICE,
    _FIXTURE_USER_ID_BOB: _FIXTURE_PRINCIPAL_BOB,
    _FIXTURE_USER_ID_ADMIN: _FIXTURE_PRINCIPAL_ADMIN,
}

# OAuth applications (service principals).
_FIXTURE_APP_GRAPH = {
    # ``id`` is the service principal object id (the GUID Entra uses to join
    # grants to events). ``appId`` is the registered application's client id.
    "id": "30000000-0000-0000-0000-000000000001",
    "appId": "11111111-1111-1111-1111-111111111111",
    "displayName": "MS Graph OAuth App (Production)",
}
_FIXTURE_APP_DORMANT = {
    "id": "30000000-0000-0000-0000-00000000000d",
    "appId": "11111111-1111-1111-1111-1111deadbeef",
    "displayName": "Legacy Dormant Addon (Production)",
}


# ---------------------------------------------------------------------------
# Sign-in event helpers (Graph /auditLogs/signIns shape)
# ---------------------------------------------------------------------------


def _location(country: str, city: str, lat: float = 0.0, lon: float = 0.0) -> dict[str, Any]:
    return {
        "countryOrRegion": country,
        "city": city,
        "state": "",
        "geoCoordinates": {"latitude": lat, "longitude": lon},
    }


def _device_detail(os_name: str = "Linux", browser: str = "FIXTURE") -> dict[str, Any]:
    return {
        "deviceId": "",
        "displayName": "",
        "operatingSystem": os_name,
        "browser": browser,
        "isCompliant": False,
        "isManaged": False,
        "trustType": "",
    }


def _status(error_code: int, reason: str = "") -> dict[str, Any]:
    return {
        "errorCode": error_code,
        "failureReason": reason,
        "additionalDetails": "",
    }


def _autonomous_system(asn: int, network: str = "Test ISP") -> dict[str, Any]:
    return {"autonomousSystemNumber": asn, "networkName": network}


def _signin_event(
    *,
    sid: str,
    upn: str,
    user_id: str,
    created: str,
    ip: str,
    country: str,
    city: str,
    asn: int,
    status: dict[str, Any],
    auth_requirement: str = "singleFactorAuthentication",
    correlation_id: str | None = None,
    auth_details: list[dict[str, Any]] | None = None,
    app_display_name: str = "Microsoft Graph",
    app_id: str = "11111111-1111-1111-1111-111111111111",
    resource_display_name: str = "Microsoft Graph",
    resource_id: str = "00000003-0000-0000-c000-000000000000",
    session_id: str = "",
    risk_event_types: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": sid,
        "createdDateTime": created,
        "userPrincipalName": upn,
        "userId": user_id,
        "userDisplayName": upn.split("@")[0].title(),
        "appDisplayName": app_display_name,
        "appId": app_id,
        "resourceDisplayName": resource_display_name,
        "resourceId": resource_id,
        "ipAddress": ip,
        "clientAppUsed": "Browser",
        "correlationId": correlation_id or sid,
        "conditionalAccessStatus": "notApplied",
        "originalRequestId": sid,
        "isInteractive": True,
        "tokenIssuerType": "AzureAD",
        "authenticationRequirement": auth_requirement,
        "authenticationDetails": auth_details or [],
        "authenticationProcessingDetails": [],
        "networkLocationDetails": [],
        "status": status,
        "deviceDetail": _device_detail(),
        "location": _location(country, city),
        "autonomousSystemNumber": asn,
        "autonomousSystem": _autonomous_system(asn),
        "riskState": "none",
        "riskLevelAggregated": "none",
        "riskLevelDuringSignIn": "none",
        "riskEventTypes_v2": risk_event_types or [],
        "homeTenantId": "00000000-0000-0000-0000-tenanttenanta",
        "sessionLifetimePolicies": [],
        # Used for token-replay correlation. Graph exposes session under
        # ``sessionLifetimePolicies`` and a ``sessionId`` claim on token
        # issuance — we surface a synthetic ``sessionId`` here so the
        # normaliser has a stable field to pull.
        "sessionId": session_id,
    }


# ---- 1. Token-replay scenario: same sessionId from two ASNs --------------
_REPLAY_SESSION = "entra-sess-replay-aaa"

_SIGNIN_TOKEN_ASN_A = _signin_event(
    sid="entra-signin-replay-aaa-001",
    upn=_FIXTURE_PRINCIPAL_ALICE,
    user_id=_FIXTURE_USER_ID_ALICE,
    created="2026-06-18T10:00:00Z",
    ip="8.8.8.8",
    country="US",
    city="Mountain View",
    asn=15169,
    status=_status(0),
    correlation_id="entra-corr-replay-aaa",
    session_id=_REPLAY_SESSION,
)

_SIGNIN_TOKEN_ASN_B = _signin_event(
    sid="entra-signin-replay-bbb-002",
    upn=_FIXTURE_PRINCIPAL_ALICE,
    user_id=_FIXTURE_USER_ID_ALICE,
    created="2026-06-18T10:18:00Z",
    ip="13.107.4.50",
    country="IE",
    city="Dublin",
    asn=8075,
    status=_status(0),
    correlation_id="entra-corr-replay-bbb",
    session_id=_REPLAY_SESSION,
)

# ---- 2. MFA fatigue: 3 deny + 1 approve for the same principal -----------
_MFA_AUTH_DETAILS_DENY: list[dict[str, Any]] = [
    {
        "authenticationStepDateTime": "2026-06-18T11:00:00Z",
        "authenticationMethod": "Microsoft Authenticator app",
        "succeeded": False,
        "authenticationStepResultDetail": "User declined the authentication",
    }
]
_MFA_AUTH_DETAILS_APPROVE: list[dict[str, Any]] = [
    {
        "authenticationStepDateTime": "2026-06-18T11:06:00Z",
        "authenticationMethod": "Microsoft Authenticator app",
        "succeeded": True,
        "authenticationStepResultDetail": "MFA completed in Azure AD",
    }
]

_SIGNIN_MFA_DENY_1 = _signin_event(
    sid="entra-signin-mfa-deny-001",
    upn=_FIXTURE_PRINCIPAL_BOB,
    user_id=_FIXTURE_USER_ID_BOB,
    created="2026-06-18T11:00:00Z",
    ip="203.0.113.55",
    country="US",
    city="Reston",
    asn=7922,
    # Entra represents MFA-deny as errorCode 50074 (Strong authentication
    # required but the user did not satisfy it). Combined with the auth
    # details below, the normaliser classifies it as MFA_DENIED.
    status=_status(50074, "MFA push declined"),
    auth_requirement="multiFactorAuthentication",
    auth_details=_MFA_AUTH_DETAILS_DENY,
    correlation_id="entra-corr-mfa-fatigue-bob",
)
_SIGNIN_MFA_DENY_2 = {
    **_SIGNIN_MFA_DENY_1,
    "id": "entra-signin-mfa-deny-002",
    "createdDateTime": "2026-06-18T11:02:00Z",
}
_SIGNIN_MFA_DENY_3 = {
    **_SIGNIN_MFA_DENY_1,
    "id": "entra-signin-mfa-deny-003",
    "createdDateTime": "2026-06-18T11:04:00Z",
}

_SIGNIN_MFA_APPROVE = _signin_event(
    sid="entra-signin-mfa-approve-004",
    upn=_FIXTURE_PRINCIPAL_BOB,
    user_id=_FIXTURE_USER_ID_BOB,
    created="2026-06-18T11:06:00Z",
    ip="203.0.113.55",
    country="US",
    city="Reston",
    asn=7922,
    status=_status(0),
    auth_requirement="multiFactorAuthentication",
    auth_details=_MFA_AUTH_DETAILS_APPROVE,
    correlation_id="entra-corr-mfa-fatigue-bob",
)

# ---- 3. Plain interactive LOGIN_SUCCESS (sanity) -------------------------
_SIGNIN_LOGIN_SUCCESS = _signin_event(
    sid="entra-signin-login-success-001",
    upn=_FIXTURE_PRINCIPAL_ALICE,
    user_id=_FIXTURE_USER_ID_ALICE,
    created="2026-06-18T09:30:00Z",
    ip="8.8.8.8",
    country="US",
    city="Mountain View",
    asn=15169,
    status=_status(0),
)

# ---- 4. Dormant OAuth grant reactivation event ---------------------------
_SIGNIN_DORMANT_REACT = _signin_event(
    sid="entra-signin-dormant-react-001",
    upn=_FIXTURE_PRINCIPAL_ALICE,
    user_id=_FIXTURE_USER_ID_ALICE,
    created="2026-06-18T12:00:00Z",
    ip="8.8.8.8",
    country="US",
    city="Mountain View",
    asn=15169,
    status=_status(0),
    app_display_name=_FIXTURE_APP_DORMANT["displayName"],
    app_id=_FIXTURE_APP_DORMANT["appId"],
    resource_display_name=_FIXTURE_APP_DORMANT["displayName"],
    resource_id=_FIXTURE_APP_DORMANT["id"],
)


# ---------------------------------------------------------------------------
# Directory audit helpers (Graph /auditLogs/directoryAudits shape)
# ---------------------------------------------------------------------------


def _initiated_by_user(upn: str, user_id: str) -> dict[str, Any]:
    return {
        "user": {
            "id": user_id,
            "displayName": upn.split("@")[0].title(),
            "userPrincipalName": upn,
            "ipAddress": "198.51.100.1",
        }
    }


def _target_app(sp: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": sp["id"],
        "displayName": sp["displayName"],
        "type": "ServicePrincipal",
        # modifiedProperties is how Entra describes audit-log diffs.
        "modifiedProperties": [],
        "userPrincipalName": None,
    }


def _target_user(upn: str, user_id: str) -> dict[str, Any]:
    return {
        "id": user_id,
        "displayName": upn.split("@")[0].title(),
        "type": "User",
        "modifiedProperties": [],
        "userPrincipalName": upn,
    }


# ---- 5. Directory audit: Add app role assignment grant to user -----------
_AUDIT_CONSENT_GRANT: dict[str, Any] = {
    "id": "entra-audit-consent-001",
    "category": "ApplicationManagement",
    "correlationId": "entra-corr-consent-001",
    "result": "success",
    "resultReason": "",
    "activityDisplayName": "Consent to application",
    "activityDateTime": "2026-06-18T08:00:00Z",
    "loggedByService": "Core Directory",
    "operationType": "Assign",
    "initiatedBy": _initiated_by_user(_FIXTURE_PRINCIPAL_ALICE, _FIXTURE_USER_ID_ALICE),
    "targetResources": [
        _target_app(_FIXTURE_APP_GRAPH),
        _target_user(_FIXTURE_PRINCIPAL_ALICE, _FIXTURE_USER_ID_ALICE),
    ],
    "additionalDetails": [
        {"key": "ConsentAction.Permissions", "value": "Mail.Read offline_access openid profile"},
        {"key": "ConsentContext.IsAdminConsent", "value": "False"},
    ],
}

# ---- 6. Directory audit: Add service principal credential (T1098.001) ----
_AUDIT_SP_CREDENTIAL_ADD: dict[str, Any] = {
    "id": "entra-audit-sp-cred-001",
    "category": "ApplicationManagement",
    "correlationId": "entra-corr-sp-cred-001",
    "result": "success",
    "resultReason": "",
    "activityDisplayName": "Add service principal credentials",
    "activityDateTime": "2026-06-18T08:30:00Z",
    "loggedByService": "Core Directory",
    "operationType": "Update",
    "initiatedBy": _initiated_by_user(_FIXTURE_PRINCIPAL_ADMIN, _FIXTURE_USER_ID_ADMIN),
    "targetResources": [_target_app(_FIXTURE_APP_GRAPH)],
    "additionalDetails": [{"key": "User-Agent", "value": "Microsoft Azure Graph Client Library"}],
}

# ---- 7. Directory audit: Set federation settings (T1556.007) -------------
_AUDIT_FEDERATION_SET: dict[str, Any] = {
    "id": "entra-audit-federation-001",
    "category": "DirectoryManagement",
    "correlationId": "entra-corr-federation-001",
    "result": "success",
    "resultReason": "",
    "activityDisplayName": "Set federation settings on domain",
    "activityDateTime": "2026-06-18T07:00:00Z",
    "loggedByService": "Core Directory",
    "operationType": "Update",
    "initiatedBy": _initiated_by_user(_FIXTURE_PRINCIPAL_ADMIN, _FIXTURE_USER_ID_ADMIN),
    "targetResources": [
        {
            "id": "partner.example.com",
            "displayName": "partner.example.com",
            "type": "Domain",
            "modifiedProperties": [],
            "userPrincipalName": None,
        }
    ],
    "additionalDetails": [],
}

# ---- 8. Directory audit: Remove member from role (privilege removed) -----
_AUDIT_ROLE_REMOVE: dict[str, Any] = {
    "id": "entra-audit-role-remove-001",
    "category": "RoleManagement",
    "correlationId": "entra-corr-role-remove-001",
    "result": "success",
    "resultReason": "",
    "activityDisplayName": "Remove member from role",
    "activityDateTime": "2026-06-18T13:00:00Z",
    "loggedByService": "Core Directory",
    "operationType": "Unassign",
    "initiatedBy": _initiated_by_user(_FIXTURE_PRINCIPAL_ADMIN, _FIXTURE_USER_ID_ADMIN),
    "targetResources": [_target_user(_FIXTURE_PRINCIPAL_BOB, _FIXTURE_USER_ID_BOB)],
    "additionalDetails": [{"key": "Role.DisplayName", "value": "Global Reader"}],
}


# ---------------------------------------------------------------------------
# Public fixture lists
# ---------------------------------------------------------------------------

ENTRA_FIXTURE_SIGNINS: list[dict[str, Any]] = [
    _SIGNIN_LOGIN_SUCCESS,
    _SIGNIN_TOKEN_ASN_A,
    _SIGNIN_TOKEN_ASN_B,
    _SIGNIN_MFA_DENY_1,
    _SIGNIN_MFA_DENY_2,
    _SIGNIN_MFA_DENY_3,
    _SIGNIN_MFA_APPROVE,
    _SIGNIN_DORMANT_REACT,
]

ENTRA_FIXTURE_DIRECTORY_AUDITS: list[dict[str, Any]] = [
    _AUDIT_FEDERATION_SET,
    _AUDIT_CONSENT_GRANT,
    _AUDIT_SP_CREDENTIAL_ADD,
    _AUDIT_ROLE_REMOVE,
]

# ---- OAuth 2.0 permission grants (Graph /oauth2PermissionGrants) --------
# These are delegated permission grants; ``principalId`` is the user GUID,
# ``clientId`` is the OAuth client's service-principal object id, ``scope``
# is a space-separated string (per Graph's serialised shape).
ENTRA_FIXTURE_OAUTH_GRANTS: list[dict[str, Any]] = [
    {
        "id": "ent_oag_fixture_user_grant_001",
        "clientId": _FIXTURE_APP_GRAPH["id"],
        "consentType": "Principal",
        "principalId": _FIXTURE_USER_ID_ALICE,
        "resourceId": "00000003-0000-0000-c000-000000000000",
        "scope": "openid profile offline_access Mail.Read",
        # Graph itself doesn't expose grantedAt / lastUsed for delegated
        # permission grants; we attach them under the same field names the
        # connector reads so the dormant-grant detector has timestamps.
        "grantedAt": "2026-05-01T09:00:00Z",
        "lastUsedAt": "2026-06-15T09:00:00Z",
        "clientDisplayName": _FIXTURE_APP_GRAPH["displayName"],
    },
    {
        "id": "ent_oag_fixture_dormant_grant_001",
        "clientId": _FIXTURE_APP_DORMANT["id"],
        # AllPrincipals (admin consent) — high-risk signal for dormant
        # reactivation. ``principalId`` is null per Graph's contract.
        "consentType": "AllPrincipals",
        "principalId": None,
        "resourceId": "00000003-0000-0000-c000-000000000000",
        "scope": "openid profile User.Read",
        "grantedAt": "2025-12-01T09:00:00Z",
        "lastUsedAt": "2026-02-01T09:00:00Z",
        "clientDisplayName": _FIXTURE_APP_DORMANT["displayName"],
    },
    {
        "id": "ent_oag_fixture_bob_active_001",
        "clientId": _FIXTURE_APP_GRAPH["id"],
        "consentType": "Principal",
        "principalId": _FIXTURE_USER_ID_BOB,
        "resourceId": "00000003-0000-0000-c000-000000000000",
        "scope": "openid profile",
        "grantedAt": "2026-06-10T09:00:00Z",
        "lastUsedAt": "2026-06-17T09:00:00Z",
        "clientDisplayName": _FIXTURE_APP_GRAPH["displayName"],
    },
]

# ---- Service-principal credential metadata (used by an enrichment tool) --
# Listed separately from grants for parity with Okta's session list — the
# Identity Hunt's T1098.001 detector reads grants + this credential surface.
ENTRA_FIXTURE_SERVICE_PRINCIPAL_CREDENTIALS: list[dict[str, Any]] = [
    {
        "servicePrincipalId": _FIXTURE_APP_GRAPH["id"],
        "displayName": _FIXTURE_APP_GRAPH["displayName"],
        "appId": _FIXTURE_APP_GRAPH["appId"],
        # ``passwordCredentials`` is what Graph returns under the SP object.
        "passwordCredentials": [
            {
                "keyId": "cred-fixture-001",
                "displayName": "rotated 2026-06-18",
                "startDateTime": "2026-06-18T08:30:00Z",
                "endDateTime": "2027-06-18T08:30:00Z",
                "hint": "Tt",
            },
        ],
        "keyCredentials": [],
    }
]
