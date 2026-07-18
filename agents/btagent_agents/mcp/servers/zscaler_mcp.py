"""Zscaler ZIA (secure web gateway) MCP server connector — Tier-2 slice (#100).

First web-proxy / secure-web-gateway connector — a telemetry domain none of the
existing connectors cover. Zscaler Internet Access sits inline on user web
traffic, so its transaction logs are the primary surface for C2 beaconing,
malware-URL blocks, and web-channel exfil. Built in the modern read-only-
telemetry style (fixtures module, lazy ``${secret:…}`` resolution, guarded live
mode, full contract tests) and mirroring
:mod:`btagent_agents.mcp.servers.cloudtrail_mcp` — no mutation / containment
capability, therefore no HITL-gated tool.

Capabilities:

- ``zscaler_weblog_search(start, end, user=None, url_contains=None,
  action=None, limit=100)`` — web-transaction log search (exact ``user`` /
  ``action`` filters, ``url``/``host`` substring).
- ``zscaler_url_summary(destination, start, end)`` — per-destination rollup:
  which users hit it, allowed vs blocked counts, categories, threat names,
  total bytes — the "who is talking to this host and did we block it" signal.
- ``zscaler_user_summary(user, start, end)`` — per-user rollup: top
  destinations, blocked count, categories, and total bytes out — the
  compromised-user / exfil triage signal (mirrors
  ``aws_cloudtrail_principal_summary``).

Secret hygiene mirrors the sibling connectors: the ZIA API key is resolved
lazily, never logged (fingerprint only via :func:`_redact_secret`), and never
returned in MCP envelopes; ``repr()`` omits it.
"""

from __future__ import annotations

import logging
import os
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from btagent_shared.utils.secrets import resolve_secret
from langchain_core.tools import tool

from btagent_agents.mcp.servers._zscaler_fixtures import ZSCALER_FIXTURE_WEBLOGS

logger = logging.getLogger("btagent.mcp.servers.zscaler")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


def _parse_zscaler_timestamp(value: str | None) -> datetime:
    """Parse an ISO-8601 timestamp into an aware ``datetime`` (epoch fallback)."""
    if not value:
        return datetime.fromtimestamp(0, tz=UTC)
    raw = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        logger.debug("zscaler: failed to parse timestamp %r", value)
        return datetime.fromtimestamp(0, tz=UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


# ---------------------------------------------------------------------------
# Secret-redaction helper for log lines local to this module
# ---------------------------------------------------------------------------
def _redact_secret(secret: str) -> str:
    """Return a safe-to-log fingerprint of the ZIA API key.

    Never returns the raw secret; a short suffix fingerprint is emitted only
    when the secret is long enough for the suffix to be non-identifying.
    """
    if not secret or len(secret) < 12:
        return "[redacted]"
    return f"[redacted:zscaler-api-key:…{secret[-4:]}]"


# ---------------------------------------------------------------------------
# Zscaler ZIA MCP server class
# ---------------------------------------------------------------------------
class ZscalerMCPServer:
    """Zscaler ZIA MCP connector with mock and real modes.

    Default mode is mock (``BTAGENT_MOCK_CONNECTORS=true``) — the connector
    never calls the ZIA API unless explicitly opted out AND an API key
    resolves. The mock path is what CI exercises; live mode is a guarded
    placeholder.
    """

    server_id: str = "zscaler"

    DEFAULT_USERNAME_REF: str = "${env:BTAGENT_ZSCALER_USERNAME}"
    DEFAULT_API_KEY_REF: str = "${secret:vault:zscaler/api_key}"
    DEFAULT_PASSWORD_REF: str = "${secret:vault:zscaler/password}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        api_base_url: str | None = None,
        username_ref: str | None = None,
        api_key_ref: str | None = None,
        password_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self.api_base_url: str = (
            api_base_url or os.getenv("BTAGENT_ZSCALER_API_URL") or "https://zsapi.zscaler.net"
        )
        self._username_ref: str = username_ref or self.DEFAULT_USERNAME_REF
        self._api_key_ref: str = api_key_ref or self.DEFAULT_API_KEY_REF
        self._password_ref: str = password_ref or self.DEFAULT_PASSWORD_REF

    # ----- safety: never put the secret in repr/str -----

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"ZscalerMCPServer(server_id={self.server_id!r}, "
            f"api_base_url={self.api_base_url!r}, mock_mode={self.mock_mode!r})"
        )

    # ----- lazy secret resolution -----

    def _get_api_key(self) -> str:
        """Resolve the ZIA API key lazily from the configured ref."""
        resolved: str = resolve_secret(self._api_key_ref)
        return resolved

    # ----- tools -----

    async def zscaler_weblog_search(
        self,
        start: str,
        end: str,
        user: str | None = None,
        url_contains: str | None = None,
        action: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Search Zscaler ZIA web-transaction logs for a time window.

        Args:
            start: ISO-8601 window start (inclusive).
            end: ISO-8601 window end (exclusive).
            user: Optional exact user filter.
            url_contains: Optional substring over the url / host.
            action: Optional exact action filter (Allowed | Blocked).
            limit: Max rows to return.

        Returns:
            Envelope with the matched web-transaction rows.
        """
        if self.mock_mode:
            return self._mock_weblog_search(start, end, user, url_contains, action, limit)
        return await self._real_weblog_search(start, end, user, url_contains, action, limit)

    async def zscaler_url_summary(
        self,
        destination: str,
        start: str,
        end: str,
    ) -> dict[str, Any]:
        """Behavioral rollup for one destination host over a window.

        Args:
            destination: The host to summarise (matched against ``host``).
            start: ISO-8601 window start (inclusive).
            end: ISO-8601 window end (exclusive).

        Returns:
            Envelope with distinct users, allowed/blocked counts, categories,
            threat names, and total bytes for the destination.
        """
        if self.mock_mode:
            return self._mock_url_summary(destination, start, end)
        return await self._real_url_summary(destination, start, end)

    async def zscaler_user_summary(
        self,
        user: str,
        start: str,
        end: str,
    ) -> dict[str, Any]:
        """Behavioral rollup for one user's web activity over a window.

        Args:
            user: The user to summarise.
            start: ISO-8601 window start (inclusive).
            end: ISO-8601 window end (exclusive).

        Returns:
            Envelope with top destinations, blocked count, categories, and
            total request bytes — the compromised-user / exfil signal.
        """
        if self.mock_mode:
            return self._mock_user_summary(user, start, end)
        return await self._real_user_summary(user, start, end)

    # ----- mock implementations -----

    def _rows_in_window(self, start: str, end: str) -> list[dict[str, Any]]:
        start_dt = _parse_zscaler_timestamp(start)
        end_dt = _parse_zscaler_timestamp(end)
        return [
            r
            for r in ZSCALER_FIXTURE_WEBLOGS
            if start_dt <= _parse_zscaler_timestamp(r.get("time")) < end_dt
        ]

    def _mock_weblog_search(
        self,
        start: str,
        end: str,
        user: str | None,
        url_contains: str | None,
        action: str | None,
        limit: int,
    ) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        for row in self._rows_in_window(start, end):
            if user is not None and row.get("user") != user:
                continue
            if url_contains is not None and url_contains not in (
                str(row.get("url", "")) + str(row.get("host", ""))
            ):
                continue
            if action is not None and str(row.get("action", "")).lower() != action.lower():
                continue
            rows.append(row)
            if len(rows) >= limit:
                break
        return {
            "status": "success",
            "is_mock": True,
            "start": start,
            "end": end,
            "user": user,
            "url_contains": url_contains,
            "action": action,
            "total": len(rows),
            "records": rows,
        }

    def _mock_url_summary(self, destination: str, start: str, end: str) -> dict[str, Any]:
        rows = [r for r in self._rows_in_window(start, end) if r.get("host") == destination]
        if not rows:
            return {
                "status": "not_found",
                "is_mock": True,
                "destination": destination,
                "message": f"No web transactions to '{destination}' in the window",
            }
        actions: Counter[str] = Counter(str(r.get("action")) for r in rows)
        return {
            "status": "success",
            "is_mock": True,
            "destination": destination,
            "start": start,
            "end": end,
            "total_requests": len(rows),
            "distinct_users": sorted({str(r.get("user")) for r in rows}),
            "actions": dict(actions),
            "categories": sorted({str(r.get("category")) for r in rows}),
            "threat_names": sorted({str(r.get("threatName")) for r in rows if r.get("threatName")}),
            "total_bytes_out": sum(int(r.get("reqSize") or 0) for r in rows),
        }

    def _mock_user_summary(self, user: str, start: str, end: str) -> dict[str, Any]:
        rows = [r for r in self._rows_in_window(start, end) if r.get("user") == user]
        if not rows:
            return {
                "status": "not_found",
                "is_mock": True,
                "user": user,
                "message": f"No web activity for user '{user}' in the window",
            }
        by_host: Counter[str] = Counter(str(r.get("host")) for r in rows)
        blocked = sum(1 for r in rows if str(r.get("action")).lower() == "blocked")
        return {
            "status": "success",
            "is_mock": True,
            "user": user,
            "start": start,
            "end": end,
            "total_requests": len(rows),
            "top_destinations": dict(by_host.most_common()),
            "blocked_count": blocked,
            "categories": sorted({str(r.get("category")) for r in rows}),
            "threat_names": sorted({str(r.get("threatName")) for r in rows if r.get("threatName")}),
            "total_bytes_out": sum(int(r.get("reqSize") or 0) for r in rows),
        }

    # ----- real implementations (placeholders, fail-safe) -----

    async def _real_weblog_search(
        self,
        start: str,
        end: str,
        user: str | None,
        url_contains: str | None,
        action: str | None,
        limit: int,
    ) -> dict[str, Any]:
        key = self._get_api_key()
        if not key or key.startswith("<unresolved:"):
            logger.warning(
                "zscaler: live-mode weblog search refused — no API key (%s)",
                _redact_secret(key),
            )
            raise NotImplementedError(
                "Zscaler live mode requires a resolvable API key (wire "
                "${secret:vault:zscaler/api_key} or set BTAGENT_ZSCALER_API_KEY)."
            )
        raise NotImplementedError("Zscaler live weblog_search not yet implemented")

    async def _real_url_summary(self, destination: str, start: str, end: str) -> dict[str, Any]:
        key = self._get_api_key()
        if not key or key.startswith("<unresolved:"):
            logger.warning(
                "zscaler: live-mode url summary refused — no API key (%s)",
                _redact_secret(key),
            )
            raise NotImplementedError("Zscaler live mode requires a resolvable API key")
        raise NotImplementedError("Zscaler live url_summary not yet implemented")

    async def _real_user_summary(self, user: str, start: str, end: str) -> dict[str, Any]:
        key = self._get_api_key()
        if not key or key.startswith("<unresolved:"):
            raise NotImplementedError("Zscaler live mode requires a resolvable API key")
        raise NotImplementedError("Zscaler live user_summary not yet implemented")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "zscaler_weblog_search",
                "description": (
                    "Search Zscaler ZIA web-transaction logs for a time window "
                    "with exact user / action filters and a url/host substring. "
                    "Rows carry the URL, category, action (Allowed/Blocked), "
                    "threat name, and request/response sizes."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "start": {"type": "string", "description": "ISO-8601 start (inclusive)"},
                        "end": {"type": "string", "description": "ISO-8601 end (exclusive)"},
                        "user": {"type": "string", "description": "Optional exact user"},
                        "url_contains": {
                            "type": "string",
                            "description": "Optional substring over the url / host",
                        },
                        "action": {
                            "type": "string",
                            "enum": ["Allowed", "Blocked"],
                            "description": "Optional exact action",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max rows to return",
                            "default": 100,
                        },
                    },
                    "required": ["start", "end"],
                },
            },
            {
                "name": "zscaler_url_summary",
                "description": (
                    "Behavioral rollup for one destination host: distinct "
                    "users, allowed/blocked counts, categories, threat names, "
                    "and total bytes — the who-is-talking-to-this-host signal."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "destination": {
                            "type": "string",
                            "description": "The host to summarise",
                        },
                        "start": {"type": "string", "description": "ISO-8601 start (inclusive)"},
                        "end": {"type": "string", "description": "ISO-8601 end (exclusive)"},
                    },
                    "required": ["destination", "start", "end"],
                },
            },
            {
                "name": "zscaler_user_summary",
                "description": (
                    "Behavioral rollup for one user's web activity: top "
                    "destinations, blocked count, categories, and total bytes "
                    "out — the compromised-user / web-exfil triage signal."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "user": {"type": "string", "description": "The user to summarise"},
                        "start": {"type": "string", "description": "ISO-8601 start (inclusive)"},
                        "end": {"type": "string", "description": "ISO-8601 end (exclusive)"},
                    },
                    "required": ["user", "start", "end"],
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances (parity with sibling connectors)
# ---------------------------------------------------------------------------
_server = ZscalerMCPServer()


@tool
async def zscaler_weblog_search(
    start: str,
    end: str,
    user: str | None = None,
    url_contains: str | None = None,
    action: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Search Zscaler ZIA web-transaction logs for a time window.

    Args:
        start: ISO-8601 window start (inclusive).
        end: ISO-8601 window end (exclusive).
        user: Optional exact user filter.
        url_contains: Optional substring over the url / host.
        action: Optional exact action filter (Allowed | Blocked).
        limit: Max rows to return.
    """
    return await _server.zscaler_weblog_search(start, end, user, url_contains, action, limit)


@tool
async def zscaler_url_summary(destination: str, start: str, end: str) -> dict[str, Any]:
    """Behavioral rollup for one destination host over a window.

    Args:
        destination: The host to summarise.
        start: ISO-8601 window start (inclusive).
        end: ISO-8601 window end (exclusive).
    """
    return await _server.zscaler_url_summary(destination, start, end)


@tool
async def zscaler_user_summary(user: str, start: str, end: str) -> dict[str, Any]:
    """Behavioral rollup for one user's web activity over a window.

    Args:
        user: The user to summarise.
        start: ISO-8601 window start (inclusive).
        end: ISO-8601 window end (exclusive).
    """
    return await _server.zscaler_user_summary(user, start, end)
