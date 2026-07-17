"""Cisco Duo MFA MCP server connector — Tier-2 slice (#100).

First Tier-2 connector (identity MFA). Follows the modern connector pattern
established by the Tier-1 identity connectors (Okta / Entra / GWS): mock-first
with a dedicated fixtures module, pure normalisers to
:mod:`btagent_shared.types.identity_hunt` shapes, lazy ``${secret:…}``
resolution, guarded live mode, full contract tests.

Capabilities:

- ``duo_auth_log_search(start, end, result=None, username=None, limit=100)``
  — Duo Admin API v2 authentication logs; normalised to
  :class:`IdentityEvent` (MFA_APPROVED / MFA_DENIED / LOGIN_SUCCESS).
- ``duo_list_users(username=None, limit=100)`` — enrolled-user records
  (status, phones, bypass-code count).
- ``duo_admin_log_search(start, end, action=None, limit=100)`` —
  administrator activity; normalised to :class:`IdentityEvent` for the
  security-relevant actions (bypass-code creation, admin creation, policy
  change) via :data:`DUO_ADMIN_EVENT_MAP`.

Result → IdentityEventKind (documented so tests and prompts agree)
------------------------------------------------------------------
Auth-log ``result``: ``success`` → MFA_APPROVED for a 2FA factor, else
LOGIN_SUCCESS; ``denied`` / ``fraud`` → MFA_DENIED (a fraud-flagged approval
is still a denial from the hunt's perspective — the user shouldn't have
approved). Admin ``action`` maps by :data:`DUO_ADMIN_EVENT_MAP` (exact
match); unmapped actions normalise to ``None`` and are dropped.

Join discipline: ``user.name`` (primary email) is the ``principal_id`` on
both auth and admin surfaces; ``access_device.ip`` is the source IP.

Secret hygiene mirrors the sibling connectors: the Admin API secret key is
resolved lazily, never logged (fingerprint only via :func:`_redact_secret`),
and never returned in MCP envelopes; ``repr()`` omits it.
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
)
from btagent_shared.utils.secrets import resolve_secret
from langchain_core.tools import tool

from btagent_agents.mcp.servers._duo_fixtures import (
    DUO_FIXTURE_ADMIN_LOGS,
    DUO_FIXTURE_AUTH_LOGS,
    DUO_FIXTURE_USERS,
)

logger = logging.getLogger("btagent.mcp.servers.duo")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"

# 2FA factors — a success on one of these is an MFA approval; anything else
# that succeeds is a plain login success.
_MFA_FACTORS: frozenset[str] = frozenset(
    {
        "duo_push",
        "phone_call",
        "passcode",
        "sms_passcode",
        "hardware_token",
        "u2f_token",
        "webauthn",
    }
)

# Administrator action → IdentityEventKind (exact match on Duo's stable
# action identifiers). Unmapped actions are dropped from the normalised list.
DUO_ADMIN_EVENT_MAP: dict[str, IdentityEventKind] = {
    "bypass_create": IdentityEventKind.CREDENTIAL_ADDED,
    "admin_create": IdentityEventKind.ROLE_ASSIGNED,
    "admin_delete": IdentityEventKind.ROLE_REMOVED,
    "user_create": IdentityEventKind.ROLE_ASSIGNED,
    "policy_update": IdentityEventKind.FEDERATION_TRUST_MODIFIED,
    "integration_create": IdentityEventKind.APP_CONSENT_GRANTED,
}


# ---------------------------------------------------------------------------
# Pure normalisers — no I/O, fully unit-testable
# ---------------------------------------------------------------------------


def _parse_duo_timestamp(value: str | None) -> datetime:
    """Parse an ISO-8601 timestamp into an aware ``datetime`` (epoch fallback)."""
    if not value:
        return datetime.fromtimestamp(0, tz=UTC)
    raw = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        logger.debug("duo: failed to parse timestamp %r", value)
        return datetime.fromtimestamp(0, tz=UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _classify_auth(result: str, factor: str) -> IdentityEventKind:
    """Map a Duo auth ``result`` (+ factor) to an :class:`IdentityEventKind`."""
    r = (result or "").strip().lower()
    if r in ("denied", "fraud"):
        return IdentityEventKind.MFA_DENIED
    # success
    if (factor or "").strip().lower() in _MFA_FACTORS:
        return IdentityEventKind.MFA_APPROVED
    return IdentityEventKind.LOGIN_SUCCESS


def normalise_auth_event(raw: dict[str, Any], *, org_id: str) -> IdentityEvent:
    """Map a single Duo authentication-log row to :class:`IdentityEvent`."""
    user = raw.get("user") or {}
    device = raw.get("access_device") or {}
    loc = device.get("location") or {}
    ts = raw.get("timestamp")
    return IdentityEvent(
        id=f"duo_auth_{user.get('key', '')}_{ts or ''}"[:200],
        org_id=org_id,
        provider=IdentityProvider.DUO,
        kind=_classify_auth(str(raw.get("result") or ""), str(raw.get("factor") or "")),
        principal_id=str(user.get("name") or "unknown@unknown"),
        app_id="",
        session_id="",
        token_id="",
        ip_address=str(device.get("ip") or ""),
        geo=GeoLocation(
            city=str(loc.get("city") or ""),
            country=str(loc.get("country") or ""),
        ),
        user_agent="",
        timestamp=_parse_duo_timestamp(ts),
        raw=raw,
    )


def normalise_admin_event(raw: dict[str, Any], *, org_id: str) -> IdentityEvent | None:
    """Map a single Duo administrator-log row to :class:`IdentityEvent`.

    Returns ``None`` when the ``action`` isn't in :data:`DUO_ADMIN_EVENT_MAP`
    — callers drop the row (it stays in the raw envelope for forensics).
    """
    action = str(raw.get("action") or "")
    kind = DUO_ADMIN_EVENT_MAP.get(action)
    if kind is None:
        return None
    ts = raw.get("timestamp")
    return IdentityEvent(
        id=f"duo_admin_{action}_{ts or ''}"[:200],
        org_id=org_id,
        # The admin who performed the action is the acting principal.
        provider=IdentityProvider.DUO,
        kind=kind,
        principal_id=str(raw.get("username") or "unknown@unknown"),
        app_id="",
        session_id="",
        token_id="",
        ip_address="",
        geo=GeoLocation(),
        user_agent="",
        timestamp=_parse_duo_timestamp(ts),
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Secret-redaction helper for log lines local to this module
# ---------------------------------------------------------------------------
def _redact_secret(secret: str) -> str:
    """Return a safe-to-log fingerprint of the Duo Admin API secret key.

    Never returns the raw secret; a short suffix fingerprint is emitted only
    when the secret is long enough for the suffix to be non-identifying.
    """
    if not secret or len(secret) < 12:
        return "[redacted]"
    return f"[redacted:duo-secret-key:…{secret[-4:]}]"


# ---------------------------------------------------------------------------
# Cisco Duo MCP server class
# ---------------------------------------------------------------------------
class DuoMCPServer:
    """Cisco Duo MFA MCP connector with mock and real modes.

    Default mode is mock (``BTAGENT_MOCK_CONNECTORS=true``) — the connector
    never calls the Duo Admin API unless explicitly opted out AND a secret
    key resolves. The mock path is what CI exercises; live mode is a guarded
    placeholder.
    """

    server_id: str = "duo"

    DEFAULT_IKEY_REF: str = "${env:BTAGENT_DUO_INTEGRATION_KEY}"
    DEFAULT_SKEY_REF: str = "${secret:vault:duo/secret_key}"
    DEFAULT_ORG_REF: str = "${env:BTAGENT_DUO_ORG_ID}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        api_hostname: str | None = None,
        integration_key_ref: str | None = None,
        secret_key_ref: str | None = None,
        org_id_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self.api_hostname: str = (
            api_hostname or os.getenv("BTAGENT_DUO_API_HOST") or "api-xxxxxxxx.duosecurity.com"
        )
        self._ikey_ref: str = integration_key_ref or self.DEFAULT_IKEY_REF
        self._skey_ref: str = secret_key_ref or self.DEFAULT_SKEY_REF
        self._org_id_ref: str = org_id_ref or self.DEFAULT_ORG_REF

    # ----- safety: never put the secret in repr/str -----

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"DuoMCPServer(server_id={self.server_id!r}, "
            f"api_hostname={self.api_hostname!r}, mock_mode={self.mock_mode!r})"
        )

    # ----- lazy secret resolution -----

    def _get_secret_key(self) -> str:
        """Resolve the Duo Admin API secret key lazily from the configured ref."""
        resolved: str = resolve_secret(self._skey_ref)
        return resolved

    def _get_org_id(self) -> str:
        """Resolve the org id stamped on normalised events."""
        resolved: str = resolve_secret(self._org_id_ref)
        return resolved or "org_duo_default"

    # ----- tools -----

    async def duo_auth_log_search(
        self,
        start: str,
        end: str,
        result: str | None = None,
        username: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Search Duo authentication logs.

        Args:
            start: ISO-8601 start (inclusive).
            end: ISO-8601 end (exclusive).
            result: Optional exact result filter (success | denied | fraud).
            username: Optional exact user.name (email) filter.
            limit: Max events to return.

        Returns:
            Envelope with raw provider rows + normalised IdentityEvent list.
        """
        if self.mock_mode:
            return self._mock_auth_log_search(start, end, result, username, limit)
        return await self._real_auth_log_search(start, end, result, username, limit)

    async def duo_list_users(
        self,
        username: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """List enrolled Duo users.

        Args:
            username: Optional exact username (email) filter.
            limit: Max users to return.

        Returns:
            Envelope with the user records.
        """
        if self.mock_mode:
            return self._mock_list_users(username, limit)
        return await self._real_list_users(username, limit)

    async def duo_admin_log_search(
        self,
        start: str,
        end: str,
        action: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Search Duo administrator activity logs.

        Args:
            start: ISO-8601 start (inclusive).
            end: ISO-8601 end (exclusive).
            action: Optional exact action filter (e.g. "bypass_create").
            limit: Max events to return.

        Returns:
            Envelope with raw + normalised IdentityEvent lists. Unmapped
            actions are dropped from the normalised list but kept in
            ``events_raw``.
        """
        if self.mock_mode:
            return self._mock_admin_log_search(start, end, action, limit)
        return await self._real_admin_log_search(start, end, action, limit)

    # ----- mock implementations -----

    def _mock_auth_log_search(
        self,
        start: str,
        end: str,
        result: str | None,
        username: str | None,
        limit: int,
    ) -> dict[str, Any]:
        org_id = self._get_org_id()
        start_dt = _parse_duo_timestamp(start)
        end_dt = _parse_duo_timestamp(end)
        events_raw: list[dict[str, Any]] = []
        for evt in DUO_FIXTURE_AUTH_LOGS:
            ts = _parse_duo_timestamp(evt.get("timestamp"))
            if ts < start_dt or ts >= end_dt:
                continue
            if result is not None and evt.get("result") != result:
                continue
            if username is not None and (evt.get("user") or {}).get("name") != username:
                continue
            events_raw.append(evt)
            if len(events_raw) >= limit:
                break

        normalised = [normalise_auth_event(e, org_id=org_id) for e in events_raw]
        return {
            "status": "success",
            "is_mock": True,
            "start": start,
            "end": end,
            "result": result,
            "username": username,
            "total": len(events_raw),
            "events_raw": events_raw,
            "events": [ev.model_dump(mode="json") for ev in normalised],
        }

    def _mock_list_users(self, username: str | None, limit: int) -> dict[str, Any]:
        raws = [u for u in DUO_FIXTURE_USERS if username is None or u.get("username") == username][
            :limit
        ]
        return {
            "status": "success",
            "is_mock": True,
            "username": username,
            "total": len(raws),
            "users": raws,
        }

    def _mock_admin_log_search(
        self,
        start: str,
        end: str,
        action: str | None,
        limit: int,
    ) -> dict[str, Any]:
        org_id = self._get_org_id()
        start_dt = _parse_duo_timestamp(start)
        end_dt = _parse_duo_timestamp(end)
        events_raw: list[dict[str, Any]] = []
        for evt in DUO_FIXTURE_ADMIN_LOGS:
            ts = _parse_duo_timestamp(evt.get("timestamp"))
            if ts < start_dt or ts >= end_dt:
                continue
            if action is not None and evt.get("action") != action:
                continue
            events_raw.append(evt)
            if len(events_raw) >= limit:
                break

        normalised = [
            ev
            for ev in (normalise_admin_event(e, org_id=org_id) for e in events_raw)
            if ev is not None
        ]
        return {
            "status": "success",
            "is_mock": True,
            "start": start,
            "end": end,
            "action": action,
            "total": len(events_raw),
            "events_raw": events_raw,
            "events": [ev.model_dump(mode="json") for ev in normalised],
        }

    # ----- real implementations (placeholders, fail-safe) -----

    async def _real_auth_log_search(
        self,
        start: str,
        end: str,
        result: str | None,
        username: str | None,
        limit: int,
    ) -> dict[str, Any]:
        key = self._get_secret_key()
        if not key or key.startswith("<unresolved:"):
            logger.warning(
                "duo: live-mode auth-log search refused — no secret key (%s)",
                _redact_secret(key),
            )
            raise NotImplementedError(
                "Cisco Duo live mode requires a resolvable Admin API secret key "
                "(wire ${secret:vault:duo/secret_key} or set BTAGENT_DUO_SECRET_KEY)."
            )
        raise NotImplementedError("Duo live auth_log_search not yet implemented")

    async def _real_list_users(self, username: str | None, limit: int) -> dict[str, Any]:
        key = self._get_secret_key()
        if not key or key.startswith("<unresolved:"):
            logger.warning(
                "duo: live-mode user list refused — no secret key (%s)",
                _redact_secret(key),
            )
            raise NotImplementedError("Cisco Duo live mode requires a resolvable secret key")
        raise NotImplementedError("Duo live list_users not yet implemented")

    async def _real_admin_log_search(
        self,
        start: str,
        end: str,
        action: str | None,
        limit: int,
    ) -> dict[str, Any]:
        key = self._get_secret_key()
        if not key or key.startswith("<unresolved:"):
            raise NotImplementedError("Cisco Duo live mode requires a resolvable secret key")
        raise NotImplementedError("Duo live admin_log_search not yet implemented")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "duo_auth_log_search",
                "description": (
                    "Search Cisco Duo authentication logs for a time window. "
                    "Returns raw rows plus normalised IdentityEvent objects "
                    "(MFA_APPROVED / MFA_DENIED / LOGIN_SUCCESS) for MFA-fatigue "
                    "and fraud hunts."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "start": {"type": "string", "description": "ISO-8601 start (inclusive)"},
                        "end": {"type": "string", "description": "ISO-8601 end (exclusive)"},
                        "result": {
                            "type": "string",
                            "enum": ["success", "denied", "fraud"],
                            "description": "Optional exact result filter",
                        },
                        "username": {
                            "type": "string",
                            "description": "Optional exact user email",
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
                "name": "duo_list_users",
                "description": (
                    "List enrolled Cisco Duo users with status, phones, and "
                    "bypass-code counts (the bypass-code count is the MFA-"
                    "sidestep signal)."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "username": {
                            "type": "string",
                            "description": "Optional exact user email",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max users to return",
                            "default": 100,
                        },
                    },
                },
            },
            {
                "name": "duo_admin_log_search",
                "description": (
                    "Search Cisco Duo administrator activity for a time window. "
                    "Returns raw + normalised IdentityEvent objects for bypass-"
                    "code creation, admin creation, and policy changes."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "start": {"type": "string", "description": "ISO-8601 start (inclusive)"},
                        "end": {"type": "string", "description": "ISO-8601 end (exclusive)"},
                        "action": {
                            "type": "string",
                            "description": "Optional exact Duo admin action",
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
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances (parity with sibling connectors)
# ---------------------------------------------------------------------------
_server = DuoMCPServer()


@tool
async def duo_auth_log_search(
    start: str,
    end: str,
    result: str | None = None,
    username: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Search Cisco Duo authentication logs for a time window.

    Args:
        start: ISO-8601 start (inclusive).
        end: ISO-8601 end (exclusive).
        result: Optional exact result filter (success | denied | fraud).
        username: Optional exact user email.
        limit: Max events to return.
    """
    return await _server.duo_auth_log_search(start, end, result, username, limit)


@tool
async def duo_list_users(
    username: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """List enrolled Cisco Duo users.

    Args:
        username: Optional exact user email.
        limit: Max users to return.
    """
    return await _server.duo_list_users(username, limit)


@tool
async def duo_admin_log_search(
    start: str,
    end: str,
    action: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Search Cisco Duo administrator activity logs.

    Args:
        start: ISO-8601 start (inclusive).
        end: ISO-8601 end (exclusive).
        action: Optional exact Duo admin action (e.g. "bypass_create").
        limit: Max events to return.
    """
    return await _server.duo_admin_log_search(start, end, action, limit)
