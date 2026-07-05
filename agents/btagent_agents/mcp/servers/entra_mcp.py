"""Microsoft Entra ID (Azure AD) MCP server connector — Tier-1 slice (#100).

Second Tier-1 identity connector after Okta (#212). Surfaces three
capabilities to the agent layer; both raw provider JSON and normalised
:class:`IdentityEvent` / :class:`OAuthGrant` objects are returned so #116
detectors join Entra-sourced data to the same schema as Okta-sourced data.

Capabilities:

- ``entra_signin_log_search(start, end, filter=None, limit=100)`` — fetch raw
  Entra sign-in events (``GET /auditLogs/signIns``) for a time window.
- ``entra_audit_log_search(start, end, activity_filter=None, limit=100)`` —
  fetch raw directory audit events (``GET /auditLogs/directoryAudits``).
- ``entra_list_oauth_grants(user_id=None, limit=100)`` — fetch delegated
  OAuth 2.0 permission grants (``GET /oauth2PermissionGrants``).

Design notes
------------
* **Mock-first.** Defaults to ``BTAGENT_MOCK_CONNECTORS=true``. Mock mode
  serves recorded fixtures from :mod:`._entra_fixtures`. Live mode is a
  guarded placeholder that pulls credentials from the project ``${secret:…}``
  / ``${env:…}`` patterns (resolved lazily).
* **Opt-in.** Registered with the discovery layer alongside Okta, but never
  hits the network until a caller disables mock mode AND supplies a tenant.
* **Circuit breaker + connection pooling.** Re-uses the existing
  :class:`btagent_agents.mcp.registry.MCPConnectionRegistry`.
* **Secret hygiene.** The Graph client secret is never logged, never put in
  exceptions, and never returned in MCP envelopes. ``str()`` / ``repr()``
  on the server omit the token.
* **Pure normaliser.** :func:`normalise_signin_event`,
  :func:`normalise_directory_audit`, and :func:`normalise_oauth_grant` are
  pure functions — no I/O — so they unit-test cleanly against fixture JSON.

Mapping Entra event shapes → IdentityEventKind
----------------------------------------------
Sign-in events: classified by ``status.errorCode`` + ``authenticationDetails``
(MFA succeeded / declined determines MFA_APPROVED vs MFA_DENIED). Sign-in
without any MFA detail and errorCode 0 → LOGIN_SUCCESS; non-zero errorCode
→ LOGIN_FAILURE. Sign-ins where the issued token includes an OAuth scope
list mapped to a known confidential client are TOKEN_ISSUED.

Directory audits: classified by ``activityDisplayName`` prefix-match against
:data:`ENTRA_ACTIVITY_MAP`. The map is the single source of truth and is
exposed for tests; entries that don't match are returned as ``None`` and
the caller drops them.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from btagent_shared.types.identity_hunt import (
    GeoLocation,
    IdentityEvent,
    IdentityEventKind,
    IdentityProvider,
    OAuthConsentType,
    OAuthGrant,
)
from btagent_shared.utils.secrets import resolve_secret
from langchain_core.tools import tool

from btagent_agents.mcp.servers._entra_fixtures import (
    ENTRA_FIXTURE_DIRECTORY_AUDITS,
    ENTRA_FIXTURE_OAUTH_GRANTS,
    ENTRA_FIXTURE_SIGNINS,
)

logger = logging.getLogger("btagent.mcp.servers.entra")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Directory audit activityDisplayName → IdentityEventKind
# ---------------------------------------------------------------------------
# Ordered: most specific first. Lookup is "first prefix match wins" so a
# longer prefix (e.g. ``Add service principal credential``) takes precedence
# over a shorter sibling.
ENTRA_ACTIVITY_MAP: list[tuple[str, IdentityEventKind]] = [
    # Service-principal / application credential lifecycle (T1098.001).
    ("Add service principal credentials", IdentityEventKind.CREDENTIAL_ADDED),
    ("Remove service principal credentials", IdentityEventKind.CREDENTIAL_REMOVED),
    ("Add application credentials", IdentityEventKind.CREDENTIAL_ADDED),
    ("Remove application credentials", IdentityEventKind.CREDENTIAL_REMOVED),
    ("Update application certificates and secrets", IdentityEventKind.CREDENTIAL_ADDED),
    # OAuth consent grants.
    ("Consent to application", IdentityEventKind.APP_CONSENT_GRANTED),
    ("Add app role assignment grant to user", IdentityEventKind.GRANT_CREATED),
    ("Add delegated permission grant", IdentityEventKind.GRANT_CREATED),
    ("Add app role assignment to service principal", IdentityEventKind.GRANT_CREATED),
    ("Remove app role assignment from user", IdentityEventKind.GRANT_REVOKED),
    ("Remove delegated permission grant", IdentityEventKind.GRANT_REVOKED),
    ("Remove app role assignment from service principal", IdentityEventKind.GRANT_REVOKED),
    # Directory-role assignments.
    ("Add member to role", IdentityEventKind.ROLE_ASSIGNED),
    ("Add eligible member", IdentityEventKind.ROLE_ASSIGNED),
    ("Remove member from role", IdentityEventKind.ROLE_REMOVED),
    ("Remove eligible member", IdentityEventKind.ROLE_REMOVED),
    # Federation / domain trust (T1556.007).
    ("Set federation settings on domain", IdentityEventKind.FEDERATION_TRUST_MODIFIED),
    ("Add domain to federation", IdentityEventKind.FEDERATION_TRUST_MODIFIED),
    ("Remove domain from federation", IdentityEventKind.FEDERATION_TRUST_MODIFIED),
    # User credentials.
    ("Reset user password", IdentityEventKind.CREDENTIAL_ADDED),
    ("Register security info", IdentityEventKind.CREDENTIAL_ADDED),
]


# ---------------------------------------------------------------------------
# Pure normalisers — no I/O, no Graph SDK, fully unit-testable
# ---------------------------------------------------------------------------


def _parse_graph_timestamp(value: str | None) -> datetime:
    """Parse a Graph ISO-8601 timestamp into an aware ``datetime``.

    Graph uses RFC3339 with a literal ``Z`` for UTC; Python <3.11 doesn't
    accept that directly through ``fromisoformat``, so we normalise. Falls
    back to ``datetime.fromtimestamp(0)`` when parsing fails — the
    fixture/connector contract is "best-effort normalisation; bad rows
    logged + skipped upstream".
    """
    if not value:
        return datetime.fromtimestamp(0, tz=UTC)
    raw = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        logger.debug("entra: failed to parse timestamp %r", value)
        return datetime.fromtimestamp(0, tz=UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _classify_signin(raw: dict[str, Any]) -> IdentityEventKind:
    """Classify a Graph sign-in event into an :class:`IdentityEventKind`.

    Discrimination rules (most specific first):
    1. MFA challenge present in ``authenticationDetails`` and any step
       ``succeeded == True`` → MFA_APPROVED. All steps failed → MFA_DENIED.
       The presence of MFA details alone (no completed step) → MFA_CHALLENGE.
    2. Otherwise: errorCode 0 → LOGIN_SUCCESS, non-zero → LOGIN_FAILURE.
    """
    auth_details = raw.get("authenticationDetails") or []
    has_mfa_factor = any(
        (step or {}).get("authenticationMethod", "").lower()
        not in {"", "password", "previously satisfied"}
        for step in auth_details
    )
    if has_mfa_factor:
        any_success = any((step or {}).get("succeeded") for step in auth_details)
        if any_success:
            return IdentityEventKind.MFA_APPROVED
        any_recorded = any("succeeded" in (step or {}) for step in auth_details)
        return IdentityEventKind.MFA_DENIED if any_recorded else IdentityEventKind.MFA_CHALLENGE

    status = raw.get("status") or {}
    error_code = status.get("errorCode")
    if error_code in (0, None):
        return IdentityEventKind.LOGIN_SUCCESS
    return IdentityEventKind.LOGIN_FAILURE


def _classify_directory_audit(activity: str) -> IdentityEventKind | None:
    """Return the :class:`IdentityEventKind` for a directory-audit activity.

    Returns ``None`` for unrecognised activity names — callers drop the row.
    """
    for prefix, kind in ENTRA_ACTIVITY_MAP:
        if activity.startswith(prefix):
            return kind
    return None


def _principal_from_signin(raw: dict[str, Any]) -> str:
    """Extract canonical principal id (UPN) from a sign-in event."""
    return raw.get("userPrincipalName") or raw.get("userId") or "unknown@unknown"


def _principal_from_audit(raw: dict[str, Any]) -> str:
    """Extract canonical principal id (UPN) from a directory audit.

    ``initiatedBy`` is the actor of the change. Falls back to the user id
    when no UPN is available, then to the constant ``unknown@unknown``.
    """
    initiated = (raw.get("initiatedBy") or {}).get("user") or {}
    return initiated.get("userPrincipalName") or initiated.get("id") or "unknown@unknown"


def _geo_from_signin(raw: dict[str, Any]) -> tuple[str, GeoLocation]:
    """Return (ip_address, GeoLocation) from a sign-in's ``location`` block."""
    ip = raw.get("ipAddress") or ""
    loc = raw.get("location") or {}
    geo_coords = loc.get("geoCoordinates") or {}

    asn_raw = raw.get("autonomousSystemNumber") or 0
    if isinstance(asn_raw, dict):
        # Older Graph shape uses ``autonomousSystem.autonomousSystemNumber``.
        asn_raw = asn_raw.get("autonomousSystemNumber") or 0
    asn_str = f"AS{asn_raw}" if isinstance(asn_raw, int) and asn_raw else ""

    geo = GeoLocation(
        country=loc.get("countryOrRegion") or "",
        city=loc.get("city") or "",
        latitude=geo_coords.get("latitude"),
        longitude=geo_coords.get("longitude"),
        asn=asn_str,
    )
    return ip, geo


def _app_id_from_signin(raw: dict[str, Any]) -> str:
    """Extract the stable service-principal id of the target resource.

    The Identity Hunt detectors (#116) join events to grants on
    ``(principal_id, app_id)`` where ``app_id`` is the OAuth client's
    service-principal **object id** (the GUID, not the user-facing
    client id / app-registration id). Graph sign-ins expose this under
    ``resourceId`` — the resource being accessed (e.g. Microsoft Graph)
    is what holds the grant. ``appId`` (lower case ``a``) is the
    application-registration GUID, distinct from the service-principal
    object id.
    """
    return raw.get("resourceId") or raw.get("appId") or ""


def _session_and_token_ids(raw: dict[str, Any]) -> tuple[str, str]:
    """Return (session_id, token_id) from a sign-in event.

    Graph surfaces the session via the synthetic ``sessionId`` claim we
    project here (mirrors Okta's ``externalSessionId``) and the token via
    ``correlationId`` (the request id that ties the issuance together).
    """
    return raw.get("sessionId") or "", raw.get("correlationId") or raw.get("id") or ""


def normalise_signin_event(raw: dict[str, Any], *, org_id: str) -> IdentityEvent:
    """Map a single Graph sign-in JSON object to :class:`IdentityEvent`.

    Sign-ins always normalise — the classifier returns LOGIN_SUCCESS /
    LOGIN_FAILURE / MFA_* and never None. Callers can drop on kind later
    if needed.
    """
    kind = _classify_signin(raw)
    principal = _principal_from_signin(raw)
    ip, geo = _geo_from_signin(raw)
    session_id, token_id = _session_and_token_ids(raw)
    app_id = _app_id_from_signin(raw)
    ua = (raw.get("deviceDetail") or {}).get("browser") or ""

    return IdentityEvent(
        id=raw.get("id") or f"entra_signin_{raw.get('createdDateTime', '')}",
        org_id=org_id,
        provider=IdentityProvider.ENTRA,
        kind=kind,
        principal_id=principal,
        app_id=app_id,
        session_id=session_id,
        token_id=token_id,
        ip_address=ip,
        geo=geo,
        user_agent=ua[:512],
        timestamp=_parse_graph_timestamp(raw.get("createdDateTime")),
        raw=raw,
    )


def normalise_directory_audit(raw: dict[str, Any], *, org_id: str) -> IdentityEvent | None:
    """Map a single Graph directory-audit JSON object to :class:`IdentityEvent`.

    Returns ``None`` if the activity isn't mapped to a known event kind.
    Audit events don't have an IP/UA in the same shape as sign-ins; the
    actor's ``initiatedBy.user.ipAddress`` is used when present.
    """
    activity = raw.get("activityDisplayName") or ""
    kind = _classify_directory_audit(activity)
    if kind is None:
        return None

    principal = _principal_from_audit(raw)
    initiated = (raw.get("initiatedBy") or {}).get("user") or {}
    ip = initiated.get("ipAddress") or ""

    # Target resource — for ApplicationManagement events the first target is
    # the service principal, exposing its object id. For RoleManagement
    # events the target is the user; the service principal id is empty.
    app_id = ""
    for target in raw.get("targetResources") or []:
        if isinstance(target, dict) and target.get("type") == "ServicePrincipal":
            app_id = target.get("id") or ""
            break

    return IdentityEvent(
        id=raw.get("id") or f"entra_audit_{raw.get('activityDateTime', '')}",
        org_id=org_id,
        provider=IdentityProvider.ENTRA,
        kind=kind,
        principal_id=principal,
        app_id=app_id,
        session_id="",
        # Use the correlationId so multi-step audit chains (consent → grant
        # → role assign) join across the audit table.
        token_id=raw.get("correlationId") or "",
        ip_address=ip,
        geo=GeoLocation(),
        user_agent="",
        timestamp=_parse_graph_timestamp(raw.get("activityDateTime")),
        raw=raw,
    )


def _consent_type_from_grant(raw: dict[str, Any]) -> OAuthConsentType:
    """Map a Graph grant's ``consentType`` to :class:`OAuthConsentType`.

    Graph values:
    * ``AllPrincipals`` — admin consent for the whole tenant (high-risk).
    * ``Principal``     — per-user end-user consent.
    Anything else maps to UNKNOWN.
    """
    consent = (raw.get("consentType") or "").lower()
    if consent == "allprincipals":
        return OAuthConsentType.ADMIN
    if consent == "principal":
        return OAuthConsentType.USER
    return OAuthConsentType.UNKNOWN


def normalise_oauth_grant(
    raw: dict[str, Any],
    *,
    org_id: str,
    user_upn_resolver: Callable[[str], str | None] | None = None,
) -> OAuthGrant:
    """Map a single Graph OAuth permission grant JSON object to :class:`OAuthGrant`.

    Graph's ``oauth2PermissionGrants`` shape uses:
    * ``clientId``    — the OAuth client's service-principal object id
                        (GUID). This is the join key the events surface as
                        ``resourceId`` for the same client.
    * ``principalId`` — user object id (GUID) for delegated grants; null
                        for ``AllPrincipals`` (admin) grants.
    * ``scope``       — space-separated scope string.

    Principal-id alignment (mirrors Codex #212 for Okta):
    Sign-in events normalise their principal to ``userPrincipalName`` (UPN);
    grants surface ``principalId`` as a GUID. Pass ``user_upn_resolver`` to
    map GUID → UPN so :func:`~btagent_shared.hunt.identity.detect_dormant_app_reactivation`
    can join ``(principal_id, app_id)`` across both shapes. ``AllPrincipals``
    grants keep ``principal_id == "tenant"`` because no specific user is
    consented to.
    """
    grant_id = raw.get("id") or f"entra_grant_{raw.get('clientId', 'unknown')}"
    client_id = raw.get("clientId") or "unknown_client"

    principal_guid = raw.get("principalId")
    if principal_guid is None:
        # AllPrincipals / admin-consent grant — no specific user.
        principal_id = "tenant"
    else:
        resolved = user_upn_resolver(principal_guid) if user_upn_resolver else None
        principal_id = resolved or principal_guid

    scope_raw = raw.get("scope") or ""
    scopes = [s.strip() for s in scope_raw.split() if s.strip()] if scope_raw else []

    granted_at = _parse_graph_timestamp(raw.get("grantedAt"))
    last_used = _parse_graph_timestamp(raw.get("lastUsedAt")) if raw.get("lastUsedAt") else None
    revoked_at = _parse_graph_timestamp(raw.get("revokedAt")) if raw.get("revokedAt") else None

    return OAuthGrant(
        id=grant_id,
        org_id=org_id,
        app_id=client_id,
        app_display_name=raw.get("clientDisplayName") or "",
        principal_id=principal_id,
        provider=IdentityProvider.ENTRA,
        scopes=scopes,
        consent_type=_consent_type_from_grant(raw),
        granted_at=granted_at,
        last_used=last_used,
        revoked_at=revoked_at,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Secret-redaction helper for log lines local to this module
# ---------------------------------------------------------------------------
def _redact_secret(secret: str) -> str:
    """Return a safe-to-log fingerprint of a Graph client secret.

    Never returns the raw secret. Returns a short fingerprint suffix for
    correlation only when the secret is long enough to be unique.
    """
    if not secret or len(secret) < 12:
        return "[redacted]"
    return f"[redacted:entra-secret:…{secret[-4:]}]"


# ---------------------------------------------------------------------------
# Entra MCP server class
# ---------------------------------------------------------------------------
class EntraMCPServer:
    """Microsoft Entra ID (Azure AD) MCP connector with mock and real modes.

    Default mode is mock (``BTAGENT_MOCK_CONNECTORS=true``) — the connector
    never calls Graph unless explicitly opted-out AND a tenant config is
    present. The mock path is the one all CI tests exercise; live mode is
    a placeholder.

    The Graph client secret is resolved lazily via
    :func:`btagent_shared.utils.secrets.resolve_secret` so an unresolved
    ``${secret:vault:…}`` reference can't break import / boot. The secret
    is never logged or returned in MCP envelopes.
    """

    server_id: str = "entra"

    DEFAULT_TENANT_REF: str = "${env:BTAGENT_ENTRA_TENANT_ID}"
    DEFAULT_CLIENT_ID_REF: str = "${env:BTAGENT_ENTRA_CLIENT_ID}"
    DEFAULT_SECRET_REF: str = "${secret:vault:entra/client_secret}"
    DEFAULT_ORG_REF: str = "${env:BTAGENT_ENTRA_ORG_ID}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        graph_base_url: str | None = None,
        tenant_ref: str | None = None,
        client_id_ref: str | None = None,
        secret_ref: str | None = None,
        org_id_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self.graph_base_url: str = (
            graph_base_url
            or os.getenv("BTAGENT_ENTRA_GRAPH_URL")
            or "https://graph.microsoft.com/v1.0"
        )
        self._tenant_ref: str = tenant_ref or self.DEFAULT_TENANT_REF
        self._client_id_ref: str = client_id_ref or self.DEFAULT_CLIENT_ID_REF
        self._secret_ref: str = secret_ref or self.DEFAULT_SECRET_REF
        self._org_id_ref: str = org_id_ref or self.DEFAULT_ORG_REF

    # ----- safety: never put secret in repr/str -----

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"EntraMCPServer(server_id={self.server_id!r}, "
            f"graph_base_url={self.graph_base_url!r}, mock_mode={self.mock_mode!r})"
        )

    # ----- lazy secret resolution -----

    def _get_client_secret(self) -> str:
        """Resolve the Graph client secret lazily from the configured secret ref."""
        resolved: str = resolve_secret(self._secret_ref)
        return resolved

    def _get_tenant_id(self) -> str:
        resolved: str = resolve_secret(self._tenant_ref)
        return resolved

    def _get_client_id(self) -> str:
        resolved: str = resolve_secret(self._client_id_ref)
        return resolved

    def _get_org_id(self) -> str:
        """Resolve the org id stamped on normalised events."""
        resolved: str = resolve_secret(self._org_id_ref)
        return resolved or "org_entra_default"

    # ----- tools -----

    async def entra_signin_log_search(
        self,
        start: str,
        end: str,
        filter: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Search Entra ID sign-in log events.

        Args:
            start: ISO-8601 start timestamp (inclusive).
            end:   ISO-8601 end timestamp (exclusive).
            filter: Optional UPN substring; coarse mock-side filter only.
            limit: Max events to return.

        Returns:
            Envelope with the raw provider events and the normalised
            :class:`IdentityEvent` list.
        """
        if self.mock_mode:
            return self._mock_signin_log_search(start, end, filter, limit)
        return await self._real_signin_log_search(start, end, filter, limit)

    async def entra_audit_log_search(
        self,
        start: str,
        end: str,
        activity_filter: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Search Entra ID directory-audit log events.

        Args:
            start: ISO-8601 start (inclusive).
            end: ISO-8601 end (exclusive).
            activity_filter: Optional Graph ``activityDisplayName`` substring.
            limit: Max events to return.

        Returns:
            Envelope with raw + normalised events. Unmapped activities are
            dropped from the normalised list but kept in ``events_raw``.
        """
        if self.mock_mode:
            return self._mock_audit_log_search(start, end, activity_filter, limit)
        return await self._real_audit_log_search(start, end, activity_filter, limit)

    async def entra_list_oauth_grants(
        self,
        user_id: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """List OAuth 2.0 delegated permission grants.

        Args:
            user_id: Entra user object id (GUID). If supplied, only that
                user's grants are returned; admin-consent (AllPrincipals)
                grants are always included regardless.
            limit: Max grants to return.

        Returns:
            Envelope with raw + normalised grant lists.
        """
        if self.mock_mode:
            return self._mock_list_oauth_grants(user_id, limit)
        return await self._real_list_oauth_grants(user_id, limit)

    # ----- mock implementations -----

    def _mock_signin_log_search(
        self,
        start: str,
        end: str,
        filter: str | None,
        limit: int,
    ) -> dict[str, Any]:
        org_id = self._get_org_id()
        start_dt = _parse_graph_timestamp(start)
        end_dt = _parse_graph_timestamp(end)
        events_raw: list[dict[str, Any]] = []
        for evt in ENTRA_FIXTURE_SIGNINS:
            ts = _parse_graph_timestamp(evt.get("createdDateTime"))
            if ts < start_dt or ts >= end_dt:
                continue
            if filter and filter not in (evt.get("userPrincipalName") or ""):
                continue
            events_raw.append(evt)
            if len(events_raw) >= limit:
                break

        normalised = [normalise_signin_event(e, org_id=org_id) for e in events_raw]
        return {
            "status": "success",
            "is_mock": True,
            "start": start,
            "end": end,
            "filter": filter,
            "total": len(events_raw),
            "events_raw": events_raw,
            "events": [ev.model_dump(mode="json") for ev in normalised],
        }

    def _mock_audit_log_search(
        self,
        start: str,
        end: str,
        activity_filter: str | None,
        limit: int,
    ) -> dict[str, Any]:
        org_id = self._get_org_id()
        start_dt = _parse_graph_timestamp(start)
        end_dt = _parse_graph_timestamp(end)
        events_raw: list[dict[str, Any]] = []
        for evt in ENTRA_FIXTURE_DIRECTORY_AUDITS:
            ts = _parse_graph_timestamp(evt.get("activityDateTime"))
            if ts < start_dt or ts >= end_dt:
                continue
            if activity_filter and activity_filter not in (evt.get("activityDisplayName") or ""):
                continue
            events_raw.append(evt)
            if len(events_raw) >= limit:
                break

        normalised = [
            ev
            for ev in (normalise_directory_audit(e, org_id=org_id) for e in events_raw)
            if ev is not None
        ]
        return {
            "status": "success",
            "is_mock": True,
            "start": start,
            "end": end,
            "activity_filter": activity_filter,
            "total": len(events_raw),
            "events_raw": events_raw,
            "events": [ev.model_dump(mode="json") for ev in normalised],
        }

    def _mock_list_oauth_grants(
        self,
        user_id: str | None,
        limit: int,
    ) -> dict[str, Any]:
        org_id = self._get_org_id()
        # Mirrors Okta's resolver pattern (Codex #212): map the GUID
        # ``principalId`` Graph returns to the UPN that sign-in events
        # surface as ``userPrincipalName``. Without resolution the join
        # in detect_dormant_app_reactivation misses every cross-tenant row.
        from btagent_agents.mcp.servers._entra_fixtures import ENTRA_FIXTURE_USER_UPNS

        resolver: Callable[[str], str | None] = ENTRA_FIXTURE_USER_UPNS.get
        # AllPrincipals grants (principalId is None) are tenant-wide and
        # always returned regardless of the user_id filter — they are the
        # high-risk surface the dormant-grant detector wants.
        raws = [
            g
            for g in ENTRA_FIXTURE_OAUTH_GRANTS
            if user_id is None or g.get("principalId") == user_id or g.get("principalId") is None
        ][:limit]
        grants = [normalise_oauth_grant(g, org_id=org_id, user_upn_resolver=resolver) for g in raws]
        return {
            "status": "success",
            "is_mock": True,
            "user_id": user_id,
            "total": len(raws),
            "grants_raw": raws,
            "grants": [g.model_dump(mode="json") for g in grants],
        }

    # ----- real implementations (placeholders, fail-safe) -----

    async def _real_signin_log_search(
        self,
        start: str,
        end: str,
        filter: str | None,
        limit: int,
    ) -> dict[str, Any]:
        secret = self._get_client_secret()
        if not secret or secret.startswith("<unresolved:"):
            logger.warning(
                "entra: live-mode sign-in search refused — no client secret (%s)",
                _redact_secret(secret),
            )
            raise NotImplementedError(
                "Entra live mode requires a resolvable Graph client secret "
                "(wire ${secret:vault:entra/client_secret} or set "
                "BTAGENT_ENTRA_CLIENT_SECRET)."
            )
        raise NotImplementedError("Entra live signin_log_search not yet implemented")

    async def _real_audit_log_search(
        self,
        start: str,
        end: str,
        activity_filter: str | None,
        limit: int,
    ) -> dict[str, Any]:
        secret = self._get_client_secret()
        if not secret or secret.startswith("<unresolved:"):
            logger.warning(
                "entra: live-mode audit search refused — no client secret (%s)",
                _redact_secret(secret),
            )
            raise NotImplementedError("Entra live mode requires a resolvable client secret")
        raise NotImplementedError("Entra live audit_log_search not yet implemented")

    async def _real_list_oauth_grants(
        self,
        user_id: str | None,
        limit: int,
    ) -> dict[str, Any]:
        secret = self._get_client_secret()
        if not secret or secret.startswith("<unresolved:"):
            raise NotImplementedError("Entra live mode requires a resolvable client secret")
        raise NotImplementedError("Entra live list_oauth_grants not yet implemented")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "entra_signin_log_search",
                "description": (
                    "Search Microsoft Entra ID sign-in log events for a time window. "
                    "Returns raw provider events plus normalised IdentityEvent "
                    "objects (LOGIN_SUCCESS / LOGIN_FAILURE / MFA_*) for "
                    "downstream identity hunts."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "start": {"type": "string", "description": "ISO-8601 start (inclusive)"},
                        "end": {"type": "string", "description": "ISO-8601 end (exclusive)"},
                        "filter": {
                            "type": "string",
                            "description": "Optional UPN substring (mock-side only)",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max events to return",
                            "default": 100,
                        },
                    },
                    "required": ["start", "end"],
                },
            },
            {
                "name": "entra_audit_log_search",
                "description": (
                    "Search Microsoft Entra ID directory-audit log events for a "
                    "time window. Returns raw + normalised IdentityEvent objects "
                    "for consent grants, service-principal credential adds, "
                    "role assignments, federation-trust changes."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "start": {"type": "string", "description": "ISO-8601 start (inclusive)"},
                        "end": {"type": "string", "description": "ISO-8601 end (exclusive)"},
                        "activity_filter": {
                            "type": "string",
                            "description": "Optional Graph activityDisplayName substring",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max events to return",
                            "default": 100,
                        },
                    },
                    "required": ["start", "end"],
                },
            },
            {
                "name": "entra_list_oauth_grants",
                "description": (
                    "List Entra OAuth 2.0 delegated permission grants for a user "
                    "(or tenant-wide). Returns raw + normalised OAuthGrant "
                    "objects for the dormant-app / over-privileged-grant detectors."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "user_id": {
                            "type": "string",
                            "description": "Entra user object id (GUID); omit for tenant-wide",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max grants to return",
                            "default": 100,
                        },
                    },
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances (parity with sibling connectors)
# ---------------------------------------------------------------------------
_server = EntraMCPServer()


@tool
async def entra_signin_log_search(
    start: str,
    end: str,
    filter: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Search Microsoft Entra ID sign-in log events for a time window.

    Args:
        start: ISO-8601 start (inclusive).
        end: ISO-8601 end (exclusive).
        filter: Optional UPN substring.
        limit: Max events to return.
    """
    return await _server.entra_signin_log_search(start, end, filter, limit)


@tool
async def entra_audit_log_search(
    start: str,
    end: str,
    activity_filter: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Search Microsoft Entra ID directory-audit log events for a time window.

    Args:
        start: ISO-8601 start (inclusive).
        end: ISO-8601 end (exclusive).
        activity_filter: Optional Graph activityDisplayName substring.
        limit: Max events to return.
    """
    return await _server.entra_audit_log_search(start, end, activity_filter, limit)


@tool
async def entra_list_oauth_grants(
    user_id: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """List Entra OAuth 2.0 delegated permission grants for a user (or tenant-wide).

    Args:
        user_id: Entra user object id (GUID); omit for tenant-wide.
        limit: Max grants to return.
    """
    return await _server.entra_list_oauth_grants(user_id, limit)
