"""Google Workspace MCP server connector — Tier-1 slice (#100).

Third Tier-1 identity connector after Okta (#212) and Entra (#221) —
completes the #116 Identity Hunt Agent's Tier-1 connector gate. Surfaces
three capabilities to the agent layer; both raw provider JSON and normalised
:class:`IdentityEvent` / :class:`OAuthGrant` objects are returned so #116
detectors join Workspace-sourced data to the same schema as Okta / Entra data.

Capabilities:

- ``gws_login_activity_search(start, end, filter=None, limit=100)`` — fetch
  raw login events (``GET /admin/reports/v1/activity/users/all/applications/login``).
- ``gws_audit_activity_search(start, end, event_filter=None, limit=100)`` —
  fetch admin + token application activity events (role assignments,
  domain-wide delegation, SSO changes, token authorize/revoke).
- ``gws_list_oauth_tokens(user_email=None, limit=100)`` — fetch per-user
  OAuth tokens (``GET /admin/directory/v1/users/{userKey}/tokens``).

Design notes
------------
* **Mock-first.** Defaults to ``BTAGENT_MOCK_CONNECTORS=true``; mock mode
  serves recorded fixtures from :mod:`._gws_fixtures`. Live mode is a
  guarded placeholder pulling credentials from ``${secret:…}`` / ``${env:…}``
  refs (resolved lazily).
* **Circuit breaker + connection pooling.** Re-uses
  :class:`btagent_agents.mcp.registry.MCPConnectionRegistry`.
* **Secret hygiene.** The service-account key is never logged, never put in
  exceptions, never returned in MCP envelopes; ``repr()`` omits it.
* **Pure normalisers.** :func:`normalise_login_event`,
  :func:`normalise_audit_event`, and :func:`normalise_oauth_token` are pure
  functions — no I/O — so they unit-test cleanly against fixture JSON.

Mapping Workspace event shapes → IdentityEventKind
--------------------------------------------------
Login events (``applications/login``): classified by the event ``name`` —
``login_success`` / ``login_failure`` map directly; ``login_verification``
(2SV challenge) maps by its ``login_challenge_status`` parameter to
MFA_APPROVED / MFA_DENIED (no status recorded → MFA_CHALLENGE).

Admin + token events: classified by event ``name`` via :data:`GWS_EVENT_MAP`
(exact match — Reports event names are stable identifiers, unlike Entra's
prose ``activityDisplayName``). Unmapped names are returned as ``None`` and
dropped from the normalised list.

Join discipline (mirrors Codex #212)
------------------------------------
Events carry ``actor.email`` so ``principal_id`` is the primary email
everywhere; Directory tokens are fetched per ``userKey`` (profile id) and the
collector stamps the resolved ``userEmail`` so grants share the same join
key. ``app_id`` is the OAuth ``client_id`` on both token events and tokens.

The Directory ``tokens`` endpoint returns no timestamps; ``grantedAt`` /
``lastUsedAt`` on a token payload are collector-side enrichment correlated
from token activity events (see the fixtures module docstring). The
normaliser reads them when present and falls back to the epoch, which the
dormant-grant detector treats as "never used since a very old grant".
"""

from __future__ import annotations

import logging
import os
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

from btagent_agents.mcp.servers._gws_fixtures import (
    GWS_FIXTURE_AUDIT_EVENTS,
    GWS_FIXTURE_LOGIN_EVENTS,
    GWS_FIXTURE_TOKENS,
)

logger = logging.getLogger("btagent.mcp.servers.gws")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Admin/token event name → IdentityEventKind
# ---------------------------------------------------------------------------
# Exact-match lookup: Reports API event ``name`` values are stable machine
# identifiers. Exposed for tests as the single source of truth.
GWS_EVENT_MAP: dict[str, IdentityEventKind] = {
    # Token application (OAuth lifecycle).
    "authorize": IdentityEventKind.GRANT_CREATED,
    "revoke": IdentityEventKind.GRANT_REVOKED,
    "request": IdentityEventKind.TOKEN_ISSUED,
    # Delegated-admin role lifecycle (T1098).
    "ASSIGN_ROLE": IdentityEventKind.ROLE_ASSIGNED,
    "UNASSIGN_ROLE": IdentityEventKind.ROLE_REMOVED,
    # Domain-wide delegation — tenant-wide app consent (high-risk).
    "AUTHORIZE_API_CLIENT_ACCESS": IdentityEventKind.APP_CONSENT_GRANTED,
    "REMOVE_API_CLIENT_ACCESS": IdentityEventKind.GRANT_REVOKED,
    # SSO / SAML federation surface (T1484.002 precursor).
    "TOGGLE_SSO_ENABLED": IdentityEventKind.FEDERATION_TRUST_MODIFIED,
    "CHANGE_SSO_SETTINGS": IdentityEventKind.FEDERATION_TRUST_MODIFIED,
    "UPDATE_SAML_CONFIG": IdentityEventKind.FEDERATION_TRUST_MODIFIED,
    # Credential lifecycle.
    "CHANGE_PASSWORD": IdentityEventKind.CREDENTIAL_ADDED,
    "CHANGE_PASSWORD_ON_NEXT_LOGIN": IdentityEventKind.CREDENTIAL_ADDED,
    "ENROLL_2SV": IdentityEventKind.CREDENTIAL_ADDED,
    "REVOKE_3LO_TOKEN": IdentityEventKind.TOKEN_REVOKED,
    "TURN_OFF_2_STEP_VERIFICATION": IdentityEventKind.CREDENTIAL_REMOVED,
}


# ---------------------------------------------------------------------------
# Pure normalisers — no I/O, fully unit-testable
# ---------------------------------------------------------------------------


def _parse_reports_timestamp(value: str | None) -> datetime:
    """Parse a Reports API RFC3339 timestamp into an aware ``datetime``.

    Falls back to the epoch on bad input — the connector contract is
    "best-effort normalisation; bad rows logged + skipped upstream".
    """
    if not value:
        return datetime.fromtimestamp(0, tz=UTC)
    raw = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        logger.debug("gws: failed to parse timestamp %r", value)
        return datetime.fromtimestamp(0, tz=UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _params(event: dict[str, Any]) -> dict[str, Any]:
    """Flatten a Reports event's ``parameters`` list to a name → value dict.

    ``multiValue`` entries keep their list; scalar ``value`` / ``boolValue``
    entries collapse to the scalar.
    """
    out: dict[str, Any] = {}
    for p in event.get("parameters") or []:
        if not isinstance(p, dict) or "name" not in p:
            continue
        if "multiValue" in p:
            out[p["name"]] = p["multiValue"]
        elif "boolValue" in p:
            out[p["name"]] = p["boolValue"]
        else:
            out[p["name"]] = p.get("value")
    return out


def _first_event(raw: dict[str, Any]) -> dict[str, Any]:
    """Return the first entry of an activity's ``events`` list (Reports
    activities carry one logical event per row in practice)."""
    events = raw.get("events") or []
    return events[0] if events and isinstance(events[0], dict) else {}


def _classify_login(raw: dict[str, Any]) -> IdentityEventKind:
    """Classify a login-application activity into an :class:`IdentityEventKind`.

    ``login_verification`` is the 2SV challenge event: its
    ``login_challenge_status`` parameter discriminates MFA_APPROVED
    (``passed``) from MFA_DENIED (``failed``); an absent status means the
    challenge was issued but not yet answered → MFA_CHALLENGE.
    """
    event = _first_event(raw)
    name = event.get("name") or ""
    if name == "login_verification":
        status = str(_params(event).get("login_challenge_status") or "").lower()
        if status == "passed":
            return IdentityEventKind.MFA_APPROVED
        if status == "failed":
            return IdentityEventKind.MFA_DENIED
        return IdentityEventKind.MFA_CHALLENGE
    if name == "login_failure":
        return IdentityEventKind.LOGIN_FAILURE
    # login_success and the rarer variants (logout excluded upstream) all
    # indicate a successful authentication for hunt purposes.
    return IdentityEventKind.LOGIN_SUCCESS


def _principal_from_activity(raw: dict[str, Any]) -> str:
    actor = raw.get("actor") or {}
    return actor.get("email") or actor.get("profileId") or "unknown@unknown"


def normalise_login_event(raw: dict[str, Any], *, org_id: str) -> IdentityEvent:
    """Map a single Reports login activity to :class:`IdentityEvent`.

    Login activities always normalise — the classifier returns
    LOGIN_SUCCESS / LOGIN_FAILURE / MFA_* and never ``None``.
    """
    ident = raw.get("id") or {}
    return IdentityEvent(
        id=str(ident.get("uniqueQualifier") or f"gws_login_{ident.get('time', '')}"),
        org_id=org_id,
        provider=IdentityProvider.GOOGLE_WORKSPACE,
        kind=_classify_login(raw),
        principal_id=_principal_from_activity(raw),
        app_id="",
        session_id="",
        token_id="",
        ip_address=raw.get("ipAddress") or "",
        geo=GeoLocation(),
        user_agent="",
        timestamp=_parse_reports_timestamp(ident.get("time")),
        raw=raw,
    )


def normalise_audit_event(raw: dict[str, Any], *, org_id: str) -> IdentityEvent | None:
    """Map a single admin/token application activity to :class:`IdentityEvent`.

    Returns ``None`` when the event name isn't in :data:`GWS_EVENT_MAP` —
    callers drop the row (it stays in the raw envelope for forensics).
    Token-application events surface the OAuth ``client_id`` as ``app_id``;
    domain-wide delegation events surface ``API_CLIENT_NAME`` the same way.
    """
    event = _first_event(raw)
    name = event.get("name") or ""
    kind = GWS_EVENT_MAP.get(name)
    if kind is None:
        return None

    params = _params(event)
    app_id = str(params.get("client_id") or params.get("API_CLIENT_NAME") or "")
    ident = raw.get("id") or {}

    return IdentityEvent(
        id=str(ident.get("uniqueQualifier") or f"gws_audit_{ident.get('time', '')}"),
        org_id=org_id,
        provider=IdentityProvider.GOOGLE_WORKSPACE,
        kind=kind,
        principal_id=_principal_from_activity(raw),
        app_id=app_id,
        session_id="",
        token_id="",
        ip_address=raw.get("ipAddress") or "",
        geo=GeoLocation(),
        user_agent="",
        timestamp=_parse_reports_timestamp(ident.get("time")),
        raw=raw,
    )


def normalise_oauth_token(raw: dict[str, Any], *, org_id: str) -> OAuthGrant:
    """Map a single Directory token JSON object to :class:`OAuthGrant`.

    ``userEmail`` (collector-stamped, see module docstring) is preferred for
    ``principal_id`` so grants join to events on the same key; the raw
    ``userKey`` profile id is the fallback. ``anonymous: true`` (unverified
    app) maps to UNKNOWN consent — Workspace end-user tokens are otherwise
    USER consent; domain-wide delegation (the ADMIN-consent analogue) never
    appears in this endpoint, it surfaces as an APP_CONSENT_GRANTED audit
    event instead.
    """
    client_id = raw.get("clientId") or "unknown_client"
    principal = raw.get("userEmail") or raw.get("userKey") or "unknown@unknown"
    consent = OAuthConsentType.UNKNOWN if raw.get("anonymous") else OAuthConsentType.USER
    granted_at = _parse_reports_timestamp(raw.get("grantedAt"))
    last_used = _parse_reports_timestamp(raw.get("lastUsedAt")) if raw.get("lastUsedAt") else None
    revoked_at = _parse_reports_timestamp(raw.get("revokedAt")) if raw.get("revokedAt") else None

    return OAuthGrant(
        id=f"gws_token_{principal}_{client_id}"[:200],
        org_id=org_id,
        app_id=client_id,
        app_display_name=raw.get("displayText") or "",
        principal_id=principal,
        provider=IdentityProvider.GOOGLE_WORKSPACE,
        scopes=[s for s in (raw.get("scopes") or []) if isinstance(s, str)],
        consent_type=consent,
        granted_at=granted_at,
        last_used=last_used,
        revoked_at=revoked_at,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Secret-redaction helper for log lines local to this module
# ---------------------------------------------------------------------------
def _redact_secret(secret: str) -> str:
    """Return a safe-to-log fingerprint of a service-account key.

    Never returns the raw secret; a short suffix fingerprint is emitted only
    when the secret is long enough for the suffix to be non-identifying.
    """
    if not secret or len(secret) < 12:
        return "[redacted]"
    return f"[redacted:gws-sa-key:…{secret[-4:]}]"


# ---------------------------------------------------------------------------
# Google Workspace MCP server class
# ---------------------------------------------------------------------------
class GoogleWorkspaceMCPServer:
    """Google Workspace MCP connector with mock and real modes.

    Default mode is mock (``BTAGENT_MOCK_CONNECTORS=true``) — the connector
    never calls the Admin SDK unless explicitly opted out AND a
    service-account key resolves. The mock path is what CI exercises; live
    mode is a guarded placeholder.

    The service-account key is resolved lazily via
    :func:`btagent_shared.utils.secrets.resolve_secret` so an unresolved
    ``${secret:vault:…}`` reference can't break import / boot; it is never
    logged or returned in MCP envelopes.
    """

    server_id: str = "gws"

    DEFAULT_CUSTOMER_REF: str = "${env:BTAGENT_GWS_CUSTOMER_ID}"
    DEFAULT_SUBJECT_REF: str = "${env:BTAGENT_GWS_ADMIN_SUBJECT}"
    DEFAULT_SA_KEY_REF: str = "${secret:vault:gws/service_account_key}"
    DEFAULT_ORG_REF: str = "${env:BTAGENT_GWS_ORG_ID}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        admin_base_url: str | None = None,
        customer_ref: str | None = None,
        subject_ref: str | None = None,
        sa_key_ref: str | None = None,
        org_id_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self.admin_base_url: str = (
            admin_base_url or os.getenv("BTAGENT_GWS_ADMIN_URL") or "https://admin.googleapis.com"
        )
        self._customer_ref: str = customer_ref or self.DEFAULT_CUSTOMER_REF
        self._subject_ref: str = subject_ref or self.DEFAULT_SUBJECT_REF
        self._sa_key_ref: str = sa_key_ref or self.DEFAULT_SA_KEY_REF
        self._org_id_ref: str = org_id_ref or self.DEFAULT_ORG_REF

    # ----- safety: never put the key in repr/str -----

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"GoogleWorkspaceMCPServer(server_id={self.server_id!r}, "
            f"admin_base_url={self.admin_base_url!r}, mock_mode={self.mock_mode!r})"
        )

    # ----- lazy secret resolution -----

    def _get_sa_key(self) -> str:
        """Resolve the service-account key lazily from the configured ref."""
        resolved: str = resolve_secret(self._sa_key_ref)
        return resolved

    def _get_customer_id(self) -> str:
        resolved: str = resolve_secret(self._customer_ref)
        return resolved

    def _get_org_id(self) -> str:
        """Resolve the org id stamped on normalised events."""
        resolved: str = resolve_secret(self._org_id_ref)
        return resolved or "org_gws_default"

    # ----- tools -----

    async def gws_login_activity_search(
        self,
        start: str,
        end: str,
        filter: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Search Workspace login-application activity events.

        Args:
            start: ISO-8601 start timestamp (inclusive).
            end:   ISO-8601 end timestamp (exclusive).
            filter: Optional actor-email substring; coarse mock-side filter.
            limit: Max events to return.

        Returns:
            Envelope with the raw provider events and the normalised
            :class:`IdentityEvent` list.
        """
        if self.mock_mode:
            return self._mock_login_activity_search(start, end, filter, limit)
        return await self._real_login_activity_search(start, end, filter, limit)

    async def gws_audit_activity_search(
        self,
        start: str,
        end: str,
        event_filter: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Search Workspace admin + token application activity events.

        Args:
            start: ISO-8601 start (inclusive).
            end: ISO-8601 end (exclusive).
            event_filter: Optional event-name substring (e.g. "ASSIGN_ROLE").
            limit: Max events to return.

        Returns:
            Envelope with raw + normalised events. Unmapped event names are
            dropped from the normalised list but kept in ``events_raw``.
        """
        if self.mock_mode:
            return self._mock_audit_activity_search(start, end, event_filter, limit)
        return await self._real_audit_activity_search(start, end, event_filter, limit)

    async def gws_list_oauth_tokens(
        self,
        user_email: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """List per-user OAuth tokens (grants) from the Directory API.

        Args:
            user_email: Primary email; if supplied, only that user's tokens
                are returned. Omit for the whole (fixture) tenant.
            limit: Max tokens to return.

        Returns:
            Envelope with raw + normalised :class:`OAuthGrant` lists.
        """
        if self.mock_mode:
            return self._mock_list_oauth_tokens(user_email, limit)
        return await self._real_list_oauth_tokens(user_email, limit)

    # ----- mock implementations -----

    def _mock_login_activity_search(
        self,
        start: str,
        end: str,
        filter: str | None,
        limit: int,
    ) -> dict[str, Any]:
        org_id = self._get_org_id()
        start_dt = _parse_reports_timestamp(start)
        end_dt = _parse_reports_timestamp(end)
        events_raw: list[dict[str, Any]] = []
        for evt in GWS_FIXTURE_LOGIN_EVENTS:
            ts = _parse_reports_timestamp((evt.get("id") or {}).get("time"))
            if ts < start_dt or ts >= end_dt:
                continue
            if filter and filter not in ((evt.get("actor") or {}).get("email") or ""):
                continue
            events_raw.append(evt)
            if len(events_raw) >= limit:
                break

        normalised = [normalise_login_event(e, org_id=org_id) for e in events_raw]
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

    def _mock_audit_activity_search(
        self,
        start: str,
        end: str,
        event_filter: str | None,
        limit: int,
    ) -> dict[str, Any]:
        org_id = self._get_org_id()
        start_dt = _parse_reports_timestamp(start)
        end_dt = _parse_reports_timestamp(end)
        events_raw: list[dict[str, Any]] = []
        for evt in GWS_FIXTURE_AUDIT_EVENTS:
            ts = _parse_reports_timestamp((evt.get("id") or {}).get("time"))
            if ts < start_dt or ts >= end_dt:
                continue
            if event_filter:
                name = (_first_event(evt)).get("name") or ""
                if event_filter not in name:
                    continue
            events_raw.append(evt)
            if len(events_raw) >= limit:
                break

        normalised = [
            ev
            for ev in (normalise_audit_event(e, org_id=org_id) for e in events_raw)
            if ev is not None
        ]
        return {
            "status": "success",
            "is_mock": True,
            "start": start,
            "end": end,
            "event_filter": event_filter,
            "total": len(events_raw),
            "events_raw": events_raw,
            "events": [ev.model_dump(mode="json") for ev in normalised],
        }

    def _mock_list_oauth_tokens(
        self,
        user_email: str | None,
        limit: int,
    ) -> dict[str, Any]:
        org_id = self._get_org_id()
        raws = [
            t for t in GWS_FIXTURE_TOKENS if user_email is None or t.get("userEmail") == user_email
        ][:limit]
        grants = [normalise_oauth_token(t, org_id=org_id) for t in raws]
        return {
            "status": "success",
            "is_mock": True,
            "user_email": user_email,
            "total": len(raws),
            "tokens_raw": raws,
            "grants": [g.model_dump(mode="json") for g in grants],
        }

    # ----- real implementations (placeholders, fail-safe) -----

    async def _real_login_activity_search(
        self,
        start: str,
        end: str,
        filter: str | None,
        limit: int,
    ) -> dict[str, Any]:
        key = self._get_sa_key()
        if not key or key.startswith("<unresolved:"):
            logger.warning(
                "gws: live-mode login search refused — no service-account key (%s)",
                _redact_secret(key),
            )
            raise NotImplementedError(
                "Google Workspace live mode requires a resolvable service-account "
                "key (wire ${secret:vault:gws/service_account_key} or set "
                "BTAGENT_GWS_SA_KEY)."
            )
        raise NotImplementedError("GWS live login_activity_search not yet implemented")

    async def _real_audit_activity_search(
        self,
        start: str,
        end: str,
        event_filter: str | None,
        limit: int,
    ) -> dict[str, Any]:
        key = self._get_sa_key()
        if not key or key.startswith("<unresolved:"):
            logger.warning(
                "gws: live-mode audit search refused — no service-account key (%s)",
                _redact_secret(key),
            )
            raise NotImplementedError("GWS live mode requires a resolvable service-account key")
        raise NotImplementedError("GWS live audit_activity_search not yet implemented")

    async def _real_list_oauth_tokens(
        self,
        user_email: str | None,
        limit: int,
    ) -> dict[str, Any]:
        key = self._get_sa_key()
        if not key or key.startswith("<unresolved:"):
            raise NotImplementedError("GWS live mode requires a resolvable service-account key")
        raise NotImplementedError("GWS live list_oauth_tokens not yet implemented")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "gws_login_activity_search",
                "description": (
                    "Search Google Workspace login activity events for a time "
                    "window. Returns raw provider events plus normalised "
                    "IdentityEvent objects (LOGIN_SUCCESS / LOGIN_FAILURE / "
                    "MFA_*) for downstream identity hunts."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "start": {"type": "string", "description": "ISO-8601 start (inclusive)"},
                        "end": {"type": "string", "description": "ISO-8601 end (exclusive)"},
                        "filter": {
                            "type": "string",
                            "description": "Optional actor-email substring (mock-side only)",
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
                "name": "gws_audit_activity_search",
                "description": (
                    "Search Google Workspace admin + token application activity "
                    "for a time window. Returns raw + normalised IdentityEvent "
                    "objects for role assignments, domain-wide delegation, SSO "
                    "changes, and OAuth token authorize/revoke."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "start": {"type": "string", "description": "ISO-8601 start (inclusive)"},
                        "end": {"type": "string", "description": "ISO-8601 end (exclusive)"},
                        "event_filter": {
                            "type": "string",
                            "description": "Optional Reports event-name substring",
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
                "name": "gws_list_oauth_tokens",
                "description": (
                    "List Google Workspace per-user OAuth tokens (Directory API). "
                    "Returns raw + normalised OAuthGrant objects for the "
                    "dormant-app / unverified-app grant detectors."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "user_email": {
                            "type": "string",
                            "description": "Primary email; omit for tenant-wide",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max tokens to return",
                            "default": 100,
                        },
                    },
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances (parity with sibling connectors)
# ---------------------------------------------------------------------------
_server = GoogleWorkspaceMCPServer()


@tool
async def gws_login_activity_search(
    start: str,
    end: str,
    filter: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Search Google Workspace login activity events for a time window.

    Args:
        start: ISO-8601 start (inclusive).
        end: ISO-8601 end (exclusive).
        filter: Optional actor-email substring.
        limit: Max events to return.
    """
    return await _server.gws_login_activity_search(start, end, filter, limit)


@tool
async def gws_audit_activity_search(
    start: str,
    end: str,
    event_filter: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Search Google Workspace admin + token application activity events.

    Args:
        start: ISO-8601 start (inclusive).
        end: ISO-8601 end (exclusive).
        event_filter: Optional Reports event-name substring.
        limit: Max events to return.
    """
    return await _server.gws_audit_activity_search(start, end, event_filter, limit)


@tool
async def gws_list_oauth_tokens(
    user_email: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """List Google Workspace per-user OAuth tokens (grants).

    Args:
        user_email: Primary email; omit for tenant-wide.
        limit: Max tokens to return.
    """
    return await _server.gws_list_oauth_tokens(user_email, limit)
