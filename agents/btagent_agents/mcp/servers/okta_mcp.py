"""Okta MCP server connector — first Tier-1 identity connector slice (#100).

Surfaces three capabilities to the agent layer:

- ``okta_system_log_search(start, end, filter=None)`` — fetch raw Okta System
  Log events for a time window. Returns the provider-native JSON shape so
  downstream consumers can normalise or audit as needed.
- ``okta_list_oauth_grants(user_id=None)`` — fetch OAuth 2.0 grants
  (consents) for a single user, or for the whole tenant when omitted. The
  raw JSON is included alongside the canonical :class:`OAuthGrant` list so
  callers can choose granularity.
- ``okta_list_sessions(user_id=None)`` — list active Okta sessions. Used
  later for token-replay / dormant-session detection by #116.

Design notes
------------
* **Mock-first.** Defaults to ``BTAGENT_MOCK_CONNECTORS=true`` (CI default).
  Mock mode serves recorded fixtures sourced from
  :mod:`tests.fixtures.identity.okta_system_log_fixture`. Live mode is a
  guarded placeholder that pulls credentials from the project ``${secret:…}``
  / ``${env:…}`` patterns (resolved lazily — never eagerly on import).
* **Opt-in.** The server is registered with the discovery layer alongside
  the other connectors, but it never hits the network until a caller
  explicitly disables mock mode AND supplies a configured tenant.
* **Circuit breaker + connection pooling.** Re-uses the existing
  :class:`btagent_agents.mcp.registry.MCPConnectionRegistry`
  singleton + :class:`btagent_agents.mcp.adapters.ResilientMCPToolAdapter`;
  no new framework code introduced here.
* **Secret hygiene.** The Okta API token is never logged, never put in
  exceptions, and never returned in MCP envelopes. ``str()`` / ``repr()``
  on the server omit the token. Any caller log line goes through
  :func:`btagent_agents.hooks._redaction.redact_secrets` upstream.
* **Pure normaliser.** :func:`normalise_system_log_event` and
  :func:`normalise_oauth_grant` are pure functions — no I/O — so they
  unit-test cleanly against fixture JSON without a real Okta tenant.

Mapping Okta event types → IdentityEventKind
--------------------------------------------
Okta System Log events use ``eventType`` keys like ``user.authentication.auth``
or ``app.oauth2.token.grant.access_token``. The mapping is keyed by the most
specific prefix; unknown event types are returned with
``IdentityEventKind.LOGIN_SUCCESS`` when ``outcome.result == "SUCCESS"`` for
``user.authentication.*`` and otherwise dropped. The mapping table is the
single source of truth and is exposed via ``OKTA_EVENT_TYPE_MAP`` for tests.
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

from btagent_agents.mcp.servers._okta_fixtures import (
    OKTA_FIXTURE_OAUTH_GRANTS,
    OKTA_FIXTURE_SESSIONS,
    OKTA_FIXTURE_SYSTEM_LOG,
)

logger = logging.getLogger("btagent.mcp.servers.okta")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"

# ---------------------------------------------------------------------------
# Event-type mapping — Okta System Log eventType → IdentityEventKind
# ---------------------------------------------------------------------------
# Ordered: most specific first. Lookup is "first prefix match wins" so a
# longer prefix (e.g. ``app.oauth2.as.token.revoke``) takes precedence over
# a shorter sibling (``app.oauth2``).
OKTA_EVENT_TYPE_MAP: list[tuple[str, IdentityEventKind]] = [
    # OAuth / token lifecycle
    ("app.oauth2.as.token.revoke", IdentityEventKind.TOKEN_REVOKED),
    ("app.oauth2.token.grant.refresh_token", IdentityEventKind.TOKEN_REFRESH),
    ("app.oauth2.token.grant.access_token", IdentityEventKind.TOKEN_ISSUED),
    ("app.oauth2.token.grant", IdentityEventKind.TOKEN_ISSUED),
    ("app.oauth2.as.consent.grant", IdentityEventKind.APP_CONSENT_GRANTED),
    ("application.user_membership.add", IdentityEventKind.GRANT_CREATED),
    ("application.user_membership.remove", IdentityEventKind.GRANT_REVOKED),
    # MFA
    ("user.authentication.auth_via_mfa", IdentityEventKind.MFA_CHALLENGE),
    ("user.mfa.factor.deactivate", IdentityEventKind.CREDENTIAL_REMOVED),
    ("user.mfa.factor.activate", IdentityEventKind.CREDENTIAL_ADDED),
    ("user.mfa.attempt_bypass", IdentityEventKind.MFA_DENIED),
    ("system.push.send_factor_verify_push", IdentityEventKind.MFA_CHALLENGE),
    # Authentication (login)
    ("user.authentication.sso", IdentityEventKind.LOGIN_SUCCESS),
    ("user.authentication.auth", IdentityEventKind.LOGIN_SUCCESS),
    ("user.session.start", IdentityEventKind.LOGIN_SUCCESS),
    ("user.session.end", IdentityEventKind.TOKEN_REVOKED),
    # Credential management
    ("user.account.privilege.grant", IdentityEventKind.ROLE_ASSIGNED),
    ("user.account.privilege.revoke", IdentityEventKind.ROLE_REMOVED),
    ("user.credential.enroll", IdentityEventKind.CREDENTIAL_ADDED),
    # Federation / IdP trust
    ("system.idp.lifecycle.update", IdentityEventKind.FEDERATION_TRUST_MODIFIED),
    ("system.idp.lifecycle.create", IdentityEventKind.FEDERATION_TRUST_MODIFIED),
    ("system.idp.lifecycle.delete", IdentityEventKind.FEDERATION_TRUST_MODIFIED),
]

# MFA outcome → IdentityEventKind override. Okta uses the same ``eventType``
# for challenge / approve / deny and discriminates via ``outcome.result``.
_MFA_OUTCOME_MAP: dict[str, IdentityEventKind] = {
    "SUCCESS": IdentityEventKind.MFA_APPROVED,
    "ALLOW": IdentityEventKind.MFA_APPROVED,
    "DENY": IdentityEventKind.MFA_DENIED,
    "FAILURE": IdentityEventKind.MFA_DENIED,
    "CHALLENGE": IdentityEventKind.MFA_CHALLENGE,
}

# Login outcome → IdentityEventKind override.
_LOGIN_OUTCOME_MAP: dict[str, IdentityEventKind] = {
    "SUCCESS": IdentityEventKind.LOGIN_SUCCESS,
    "ALLOW": IdentityEventKind.LOGIN_SUCCESS,
    "FAILURE": IdentityEventKind.LOGIN_FAILURE,
    "DENY": IdentityEventKind.LOGIN_FAILURE,
}


# ---------------------------------------------------------------------------
# Pure normalisers — no I/O, no Okta SDK, fully unit-testable
# ---------------------------------------------------------------------------


def _parse_okta_timestamp(value: str | None) -> datetime:
    """Parse an Okta ISO-8601 timestamp into an aware ``datetime``.

    Okta uses RFC3339 with a literal ``Z`` for UTC; Python <3.11 doesn't
    accept that directly through ``fromisoformat``, so we normalise.
    Falls back to ``datetime.min`` (UTC-naive promoted to aware) when
    parsing fails, rather than raising — the fixture/connector contract
    is "best-effort normalisation; bad rows logged + skipped upstream".
    """
    if not value:
        return datetime.fromtimestamp(0, tz=UTC)
    raw = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        logger.debug("okta: failed to parse timestamp %r", value)
        return datetime.fromtimestamp(0, tz=UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _principal_from_event(raw: dict[str, Any]) -> str:
    """Extract the canonical principal id (alternateId / UPN) from an event."""
    actor = raw.get("actor") or {}
    return (
        actor.get("alternateId") or actor.get("displayName") or actor.get("id") or "unknown@unknown"
    )


def _classify_event_type(event_type: str, outcome_result: str) -> IdentityEventKind | None:
    """Return the :class:`IdentityEventKind` for an Okta ``eventType``.

    Returns ``None`` if the event type doesn't map to anything we track —
    callers drop the event rather than fabricate a kind.
    """
    # MFA family — discriminate by outcome
    if event_type.startswith("user.authentication.auth_via_mfa"):
        return _MFA_OUTCOME_MAP.get(outcome_result, IdentityEventKind.MFA_CHALLENGE)
    if event_type.startswith("system.push.send_factor_verify_push"):
        # Push challenge — outcome ALLOW / DENY tells us what happened
        return _MFA_OUTCOME_MAP.get(outcome_result, IdentityEventKind.MFA_CHALLENGE)

    # Login family — discriminate by outcome
    if event_type == "user.authentication.auth" or event_type.startswith("user.authentication.sso"):
        return _LOGIN_OUTCOME_MAP.get(outcome_result, IdentityEventKind.LOGIN_SUCCESS)
    if event_type == "user.session.start":
        return _LOGIN_OUTCOME_MAP.get(outcome_result, IdentityEventKind.LOGIN_SUCCESS)

    # Generic prefix-match — most specific first
    for prefix, kind in OKTA_EVENT_TYPE_MAP:
        if event_type.startswith(prefix):
            return kind

    return None


def _geo_from_event(raw: dict[str, Any]) -> tuple[str, GeoLocation]:
    """Return (ip_address, GeoLocation) from an Okta event's ``client`` block."""
    client = raw.get("client") or {}
    ip = client.get("ipAddress") or ""

    geo_ctx = client.get("geographicalContext") or {}
    geolocation_raw = geo_ctx.get("geolocation") or {}

    # Okta exposes ASN under client.zone or under securityContext.asNumber
    sec_ctx = raw.get("securityContext") or {}
    asn_raw = sec_ctx.get("asNumber") or sec_ctx.get("asn") or ""
    asn_str = (
        f"AS{asn_raw}"
        if isinstance(asn_raw, int) and asn_raw
        else (str(asn_raw) if asn_raw else "")
    )

    geo = GeoLocation(
        country=geo_ctx.get("country", "") or "",
        city=geo_ctx.get("city", "") or "",
        latitude=geolocation_raw.get("lat"),
        longitude=geolocation_raw.get("lon"),
        asn=asn_str,
    )
    return ip, geo


def _session_and_token_ids(raw: dict[str, Any]) -> tuple[str, str]:
    """Return (session_id, token_id) — Okta calls them authenticationContext.

    For OAuth events the access_token id appears under
    ``debugContext.debugData.dtHash`` or ``target[].id`` for the token; we
    use a tolerant lookup so the normaliser still produces useful output
    when fields are missing.
    """
    authn_ctx = raw.get("authenticationContext") or {}
    session_id = authn_ctx.get("externalSessionId") or authn_ctx.get("sessionId") or ""

    debug_data = (raw.get("debugContext") or {}).get("debugData") or {}
    token_id = (
        debug_data.get("dtHash")
        or debug_data.get("requestId")  # last-resort correlation
        or ""
    )
    # If a target of type AccessToken is present, prefer its id.
    for target in raw.get("target") or []:
        if isinstance(target, dict) and target.get("type") == "AccessToken":
            tid = target.get("id") or ""
            if tid:
                token_id = tid
                break
    return session_id, token_id


def _app_id_from_event(raw: dict[str, Any]) -> str:
    """Extract the stable OAuth client/app id from an event's ``target`` array.

    For ``AppInstance`` and ``ClientApp`` targets Okta's ``id`` is the stable
    client identifier (``0oa…``); ``alternateId`` is the **display label**
    and can collide across tenants or differ from the registered ``clientId``.
    ``normalise_oauth_grant`` stores grants keyed on ``clientId``, and the
    #116 ``detect_dormant_app_reactivation`` joins events ↔ grants on
    ``(principal_id, app_id)``, so both sides must agree on the stable id —
    falling back to ``alternateId`` only when no stable id is present (very
    old log shapes / partial enrichment).
    """
    for target in raw.get("target") or []:
        if not isinstance(target, dict):
            continue
        if target.get("type") in {"AppInstance", "ClientApp", "AppUser"}:
            return target.get("id") or target.get("alternateId") or ""
    return ""


def normalise_system_log_event(
    raw: dict[str, Any],
    *,
    org_id: str,
) -> IdentityEvent | None:
    """Map a single Okta System Log event JSON object to :class:`IdentityEvent`.

    Returns ``None`` if the event type doesn't map to anything #116's
    detectors consume — callers should drop the row.

    Parameters
    ----------
    raw:
        The Okta System Log event as returned by ``GET /api/v1/logs``.
    org_id:
        The org id to stamp on the normalised event (constant per tenant).
    """
    event_type = raw.get("eventType") or ""
    outcome = (raw.get("outcome") or {}).get("result") or ""
    kind = _classify_event_type(event_type, outcome)
    if kind is None:
        return None

    principal = _principal_from_event(raw)
    ip, geo = _geo_from_event(raw)
    session_id, token_id = _session_and_token_ids(raw)
    app_id = _app_id_from_event(raw)
    ua = ((raw.get("client") or {}).get("userAgent") or {}).get("rawUserAgent") or ""

    return IdentityEvent(
        id=raw.get("uuid") or f"okta_evt_{raw.get('published', '')}",
        org_id=org_id,
        provider=IdentityProvider.OKTA,
        kind=kind,
        principal_id=principal,
        app_id=app_id,
        session_id=session_id,
        token_id=token_id,
        ip_address=ip,
        geo=geo,
        user_agent=ua[:512],
        timestamp=_parse_okta_timestamp(raw.get("published")),
        raw=raw,
    )


def _consent_type_from_grant(raw: dict[str, Any]) -> OAuthConsentType:
    """Map an Okta grant's ``status`` / ``source`` to :class:`OAuthConsentType`."""
    source = (raw.get("source") or "").upper()
    if "ADMIN" in source:
        return OAuthConsentType.ADMIN
    if "PRE_AUTHORIZED" in source or "PREAUTHORIZED" in source:
        return OAuthConsentType.PRE_AUTHORIZED
    if "END_USER" in source or "USER" in source:
        return OAuthConsentType.USER
    return OAuthConsentType.UNKNOWN


def normalise_oauth_grant(
    raw: dict[str, Any],
    *,
    org_id: str,
    user_login_resolver: Callable[[str], str | None] | None = None,
) -> OAuthGrant:
    """Map a single Okta OAuth grant JSON object to :class:`OAuthGrant`.

    Okta returns one grant object per scope by default; tests aggregate by
    (client_id, principal_id) where needed.

    Principal-id alignment (Codex #212): System Log events normalise their
    principal to ``actor.alternateId`` (UPN / login email), but a grant's raw
    ``userId`` is the Okta user id (``00u…``). The #116
    ``detect_dormant_app_reactivation`` joins on ``(principal_id, app_id)``,
    so both sides MUST use the same form. Pass ``user_login_resolver`` (e.g.
    a closure over Okta's ``GET /api/v1/users/{userId}`` ``profile.login``)
    to resolve the grant's ``userId`` to the UPN events use. Without the
    resolver the grant retains its raw ``userId``; that is still safe for
    grants whose ``userId`` already IS a login (legacy / pre-resolved
    fixtures), but live integrations should always pass the resolver.
    """
    grant_id = raw.get("id") or f"okta_grant_{raw.get('clientId', 'unknown')}"
    client_id = raw.get("clientId") or "unknown_client"
    raw_user_id = raw.get("userId") or raw.get("subject") or "unknown_user"
    resolved_login = user_login_resolver(raw_user_id) if user_login_resolver else None
    principal_id = resolved_login or raw_user_id

    scopes_raw = raw.get("scopes")
    if scopes_raw is None:
        scope = raw.get("scopeId") or raw.get("scope") or ""
        scopes = [scope] if scope else []
    elif isinstance(scopes_raw, str):
        scopes = [s.strip() for s in scopes_raw.split() if s.strip()]
    else:
        scopes = [str(s) for s in scopes_raw]

    granted_at = _parse_okta_timestamp(raw.get("created") or raw.get("issuedAt"))
    last_used = _parse_okta_timestamp(raw.get("lastUpdated")) if raw.get("lastUpdated") else None
    revoked_at = _parse_okta_timestamp(raw.get("revokedAt")) if raw.get("revokedAt") else None

    return OAuthGrant(
        id=grant_id,
        org_id=org_id,
        app_id=client_id,
        app_display_name=raw.get("clientDisplayName") or raw.get("clientName") or "",
        principal_id=principal_id,
        provider=IdentityProvider.OKTA,
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
def _redact_token(token: str) -> str:
    """Return a safe-to-log fingerprint of the Okta API token.

    Never returns the raw token. Returns a short fingerprint suffix for
    correlation only when the token is long enough to be uniquely
    identifiable.
    """
    if not token or len(token) < 12:
        return "[redacted]"
    return f"[redacted:okta-token:…{token[-4:]}]"


# ---------------------------------------------------------------------------
# Okta MCP server class
# ---------------------------------------------------------------------------
class OktaMCPServer:
    """Okta MCP connector with mock and real modes.

    Default mode is mock (``BTAGENT_MOCK_CONNECTORS=true``) — the connector
    never calls Okta unless explicitly opted-out AND a tenant config is
    present. The mock path is the one all CI tests exercise; live mode is
    a placeholder.

    The Okta API token is resolved lazily via
    :func:`btagent_shared.utils.secrets.resolve_secret` so an unresolved
    ``${secret:vault:…}`` reference can't break import / boot. The token
    is never logged or returned in MCP envelopes.
    """

    server_id: str = "okta"

    # Default secret reference for the API token. Resolved lazily — the
    # string is fine to keep in attributes; only ``_get_api_token`` ever
    # resolves it.
    DEFAULT_TOKEN_REF: str = "${secret:vault:okta/api_token}"
    DEFAULT_ORG_REF: str = "${env:BTAGENT_OKTA_ORG_ID}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        tenant_url: str | None = None,
        token_ref: str | None = None,
        org_id_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self.tenant_url: str = (
            tenant_url or os.getenv("BTAGENT_OKTA_TENANT_URL") or "https://example.okta.com"
        )
        self._token_ref: str = token_ref or self.DEFAULT_TOKEN_REF
        self._org_id_ref: str = org_id_ref or self.DEFAULT_ORG_REF

    # ----- safety: no token in repr/str -----

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"OktaMCPServer(server_id={self.server_id!r}, "
            f"tenant_url={self.tenant_url!r}, mock_mode={self.mock_mode!r})"
        )

    # ----- lazy secret resolution -----

    def _get_api_token(self) -> str:
        """Resolve the Okta API token lazily from the configured secret ref.

        Never raises on unresolved refs in non-prod — the resolver returns
        a ``<unresolved:…>`` placeholder. Live-mode methods check for
        that placeholder and refuse to call Okta.
        """
        resolved: str = resolve_secret(self._token_ref)
        return resolved

    def _get_org_id(self) -> str:
        """Resolve the org id stamped on normalised events."""
        resolved: str = resolve_secret(self._org_id_ref)
        return resolved or "org_okta_default"

    # ----- tools -----

    async def okta_system_log_search(
        self,
        start: str,
        end: str,
        filter: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Search Okta System Log events.

        Args:
            start: ISO-8601 start timestamp (inclusive).
            end:   ISO-8601 end timestamp (exclusive).
            filter: Optional Okta SCIM-style filter (``eventType eq …``).
            limit: Max events to return.

        Returns:
            Envelope with the raw provider events and the normalised
            :class:`IdentityEvent` list. ``is_mock`` is set when mock data
            is served.
        """
        if self.mock_mode:
            return self._mock_system_log_search(start, end, filter, limit)
        return await self._real_system_log_search(start, end, filter, limit)

    async def okta_list_oauth_grants(
        self,
        user_id: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """List OAuth grants for ``user_id`` or for the whole tenant.

        Args:
            user_id: If supplied, only that user's grants are returned.
            limit: Max grants to return.

        Returns:
            Envelope with raw + normalised grant lists.
        """
        if self.mock_mode:
            return self._mock_list_oauth_grants(user_id, limit)
        return await self._real_list_oauth_grants(user_id, limit)

    async def okta_list_sessions(
        self,
        user_id: str | None = None,
    ) -> dict[str, Any]:
        """List active Okta sessions for ``user_id`` (or tenant-wide).

        Used by #116's planned stale-session / token-replay detectors.
        """
        if self.mock_mode:
            return self._mock_list_sessions(user_id)
        return await self._real_list_sessions(user_id)

    # ----- mock implementations -----

    def _mock_system_log_search(
        self,
        start: str,
        end: str,
        filter: str | None,
        limit: int,
    ) -> dict[str, Any]:
        org_id = self._get_org_id()
        events_raw: list[dict[str, Any]] = []
        # Coarse fixture filter — return events whose published timestamp
        # falls within [start, end). Tests pass an open enough window that
        # the full fixture is returned.
        start_dt = _parse_okta_timestamp(start)
        end_dt = _parse_okta_timestamp(end)
        for evt in OKTA_FIXTURE_SYSTEM_LOG:
            ts = _parse_okta_timestamp(evt.get("published"))
            if ts < start_dt or ts >= end_dt:
                continue
            if filter and filter not in (evt.get("eventType") or ""):
                continue
            events_raw.append(evt)
            if len(events_raw) >= limit:
                break

        normalised = [
            ev
            for ev in (normalise_system_log_event(e, org_id=org_id) for e in events_raw)
            if ev is not None
        ]
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

    def _mock_list_oauth_grants(
        self,
        user_id: str | None,
        limit: int,
    ) -> dict[str, Any]:
        org_id = self._get_org_id()
        # Codex #212: normalise grant principal to the same form (UPN /
        # alternateId) that System Log events use, so detect_dormant_app
        # can join (principal_id, app_id). In mock mode the resolver is the
        # fixture login map; in live mode a real connector path would close
        # over a cached ``GET /api/v1/users/{userId}`` ``profile.login`` call.
        from btagent_agents.mcp.servers._okta_fixtures import OKTA_FIXTURE_USER_LOGINS

        resolver: Callable[[str], str | None] = OKTA_FIXTURE_USER_LOGINS.get
        raws = [
            g for g in OKTA_FIXTURE_OAUTH_GRANTS if user_id is None or g.get("userId") == user_id
        ][:limit]
        grants = [
            normalise_oauth_grant(g, org_id=org_id, user_login_resolver=resolver) for g in raws
        ]
        return {
            "status": "success",
            "is_mock": True,
            "user_id": user_id,
            "total": len(raws),
            "grants_raw": raws,
            "grants": [g.model_dump(mode="json") for g in grants],
        }

    def _mock_list_sessions(self, user_id: str | None) -> dict[str, Any]:
        raws = [s for s in OKTA_FIXTURE_SESSIONS if user_id is None or s.get("userId") == user_id]
        return {
            "status": "success",
            "is_mock": True,
            "user_id": user_id,
            "total": len(raws),
            "sessions": raws,
        }

    # ----- real implementations (placeholders, fail-safe) -----

    async def _real_system_log_search(
        self,
        start: str,
        end: str,
        filter: str | None,
        limit: int,
    ) -> dict[str, Any]:
        token = self._get_api_token()
        if not token or token.startswith("<unresolved:"):
            # Never log the token, just its fingerprint.
            logger.warning(
                "okta: live-mode system log search refused — no API token (%s)",
                _redact_token(token),
            )
            raise NotImplementedError(
                "Okta live mode requires a resolvable API token "
                "(set BTAGENT_OKTA_API_TOKEN or wire ${secret:vault:okta/api_token})."
            )
        # Live HTTP call deferred to the live-rollout PR. The skeleton stays
        # here so a future change can drop in an httpx client without
        # touching the contract.
        raise NotImplementedError("Okta live system_log_search not yet implemented")

    async def _real_list_oauth_grants(
        self,
        user_id: str | None,
        limit: int,
    ) -> dict[str, Any]:
        raise NotImplementedError("Okta live list_oauth_grants not yet implemented")

    async def _real_list_sessions(self, user_id: str | None) -> dict[str, Any]:
        raise NotImplementedError("Okta live list_sessions not yet implemented")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "okta_system_log_search",
                "description": (
                    "Search Okta System Log events for a time window. "
                    "Returns raw provider events plus normalised "
                    "IdentityEvent objects for downstream identity hunts."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "start": {
                            "type": "string",
                            "description": "ISO-8601 start (inclusive)",
                        },
                        "end": {
                            "type": "string",
                            "description": "ISO-8601 end (exclusive)",
                        },
                        "filter": {
                            "type": "string",
                            "description": "Optional Okta eventType substring",
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
                "name": "okta_list_oauth_grants",
                "description": (
                    "List OAuth 2.0 grants (consents) for a user or for the whole "
                    "tenant. Returns raw + normalised OAuthGrant objects "
                    "for the dormant-app / over-privileged-grant detectors."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "user_id": {
                            "type": "string",
                            "description": "Okta user id (omit for tenant-wide)",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max grants to return",
                            "default": 100,
                        },
                    },
                },
            },
            {
                "name": "okta_list_sessions",
                "description": (
                    "List active Okta sessions for a user or for the whole tenant. "
                    "Used by token-replay / stale-session detectors."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "user_id": {
                            "type": "string",
                            "description": "Okta user id (omit for tenant-wide)",
                        },
                    },
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances (parity with sibling connectors)
# ---------------------------------------------------------------------------
_server = OktaMCPServer()


@tool
async def okta_system_log_search(
    start: str,
    end: str,
    filter: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Search Okta System Log events for a time window.

    Args:
        start: ISO-8601 start (inclusive).
        end: ISO-8601 end (exclusive).
        filter: Optional Okta eventType substring.
        limit: Max events to return.
    """
    return await _server.okta_system_log_search(start, end, filter, limit)


@tool
async def okta_list_oauth_grants(
    user_id: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """List OAuth 2.0 grants for a user (or tenant-wide).

    Args:
        user_id: Okta user id (omit for tenant-wide).
        limit: Max grants to return.
    """
    return await _server.okta_list_oauth_grants(user_id, limit)


@tool
async def okta_list_sessions(user_id: str | None = None) -> dict[str, Any]:
    """List active Okta sessions for a user (or tenant-wide).

    Args:
        user_id: Okta user id (omit for tenant-wide).
    """
    return await _server.okta_list_sessions(user_id)
