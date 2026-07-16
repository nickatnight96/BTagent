"""Zeek / Corelight MCP server connector — Tier-1 slice (#100).

First network-sensor connector ("Behavioral network analytics —
irreplaceable for hunt"). Built in the modern Tier-1 style (fixtures module,
lazy ``${secret:…}`` resolution, guarded live mode, full contract tests).

A Zeek sensor is **passive**: unlike the EDR connectors there is no
mutation / containment capability and therefore no HITL-gated tool — all
three capabilities are read-only queries.

Capabilities:

- ``zeek_log_search(log_type, start, end, filter_expr=None, limit=100)`` —
  search one Zeek log stream (``conn`` / ``dns`` / ``ssl`` / ``notice``).
  The mock applies conjunctive quoted-literal narrowing (see below).
- ``zeek_list_notices(start=None, end=None, note_contains=None, limit=100)``
  — notice.log entries (Zeek's built-in + Corelight-package detections).
- ``zeek_connection_summary(host, start, end)`` — behavioral rollup for one
  originating host over conn.log: totals, distinct peers, per-destination
  connection counts and byte volumes, and long-lived connections. This is
  pure aggregation over the sensor data — the beaconing / exfil signal the
  Tier-1 table calls out.

Mock filter semantics (documented so tests and prompts agree)
-------------------------------------------------------------
``filter_expr`` is not interpreted as a real Zeek/Corelight query: the mock
keeps rows containing **every** double-quoted string literal in the
expression (case-insensitive substring over the row's JSON), then applies
the ``start``/``end`` window on ``ts`` and the row limit.
``id.resp_h == "198.51.100.150"`` therefore narrows exactly as an analyst
would expect; arbitrary operators degrade gracefully to "no extra
filtering". An unknown log type returns an ``unknown_log`` error envelope
listing the streams the mock serves.

Secret hygiene mirrors the sibling connectors: the Corelight API token is
resolved lazily, never logged (fingerprint only via :func:`_redact_secret`),
and never returned in MCP envelopes; ``repr()`` omits it.
"""

from __future__ import annotations

import logging
import os
import re
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from btagent_shared.utils.secrets import resolve_secret
from langchain_core.tools import tool

from btagent_agents.mcp.servers._zeek_fixtures import ZEEK_FIXTURE_LOGS

logger = logging.getLogger("btagent.mcp.servers.zeek")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"

# A conn-log duration (seconds) above this counts as "long-lived" in the
# behavioral summary — tuned to catch interactive exfil sessions, not web
# keep-alives.
LONG_LIVED_THRESHOLD_SECONDS: float = 300.0

_QUOTED_LITERAL = re.compile(r'"([^"]+)"')


def _filter_literals(expr: str | None) -> list[str]:
    """Extract the double-quoted string literals from a filter expression."""
    return _QUOTED_LITERAL.findall(expr or "")


def _parse_zeek_timestamp(value: str | None) -> datetime:
    """Parse an ISO-8601 timestamp into an aware ``datetime`` (epoch fallback)."""
    if not value:
        return datetime.fromtimestamp(0, tz=UTC)
    raw = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        logger.debug("zeek: failed to parse timestamp %r", value)
        return datetime.fromtimestamp(0, tz=UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


# ---------------------------------------------------------------------------
# Secret-redaction helper for log lines local to this module
# ---------------------------------------------------------------------------
def _redact_secret(secret: str) -> str:
    """Return a safe-to-log fingerprint of the Corelight API token.

    Never returns the raw secret; a short suffix fingerprint is emitted only
    when the secret is long enough for the suffix to be non-identifying.
    """
    if not secret or len(secret) < 12:
        return "[redacted]"
    return f"[redacted:zeek-api-token:…{secret[-4:]}]"


# ---------------------------------------------------------------------------
# Zeek / Corelight MCP server class
# ---------------------------------------------------------------------------
class ZeekMCPServer:
    """Zeek / Corelight MCP connector with mock and real modes.

    Default mode is mock (``BTAGENT_MOCK_CONNECTORS=true``) — the connector
    never calls a Corelight sensor / data broker unless explicitly opted out
    AND an API token resolves. The mock path is what CI exercises; live mode
    is a guarded placeholder.
    """

    server_id: str = "zeek"

    DEFAULT_API_TOKEN_REF: str = "${secret:vault:zeek/corelight_api_token}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        api_base_url: str | None = None,
        api_token_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self.api_base_url: str = (
            api_base_url
            or os.getenv("BTAGENT_ZEEK_API_URL")
            or "https://corelight.internal.example"
        )
        self._api_token_ref: str = api_token_ref or self.DEFAULT_API_TOKEN_REF

    # ----- safety: never put the token in repr/str -----

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"ZeekMCPServer(server_id={self.server_id!r}, "
            f"api_base_url={self.api_base_url!r}, mock_mode={self.mock_mode!r})"
        )

    # ----- lazy secret resolution -----

    def _get_api_token(self) -> str:
        """Resolve the Corelight API token lazily from the configured ref."""
        resolved: str = resolve_secret(self._api_token_ref)
        return resolved

    # ----- tools -----

    async def zeek_log_search(
        self,
        log_type: str,
        start: str,
        end: str,
        filter_expr: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Search one Zeek log stream for a time window.

        Args:
            log_type: conn | dns | ssl | notice.
            start: ISO-8601 window start (inclusive).
            end: ISO-8601 window end (exclusive).
            filter_expr: Optional expression; quoted literals narrow the mock.
            limit: Max rows to return.

        Returns:
            Envelope with the matched rows and the mock's applied literal
            filters (see the module docstring for the mock semantics).
        """
        if self.mock_mode:
            return self._mock_log_search(log_type, start, end, filter_expr, limit)
        return await self._real_log_search(log_type, start, end, filter_expr, limit)

    async def zeek_list_notices(
        self,
        start: str | None = None,
        end: str | None = None,
        note_contains: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """List Zeek notice.log entries (built-in + package detections).

        Args:
            start: Optional ISO-8601 window start (inclusive).
            end: Optional ISO-8601 window end (exclusive).
            note_contains: Optional substring over the ``note`` type
                (e.g. "DNS_Tunneling", "Scan::").
            limit: Max notices to return.

        Returns:
            Envelope with the notice rows.
        """
        if self.mock_mode:
            return self._mock_list_notices(start, end, note_contains, limit)
        return await self._real_list_notices(start, end, note_contains, limit)

    async def zeek_connection_summary(
        self,
        host: str,
        start: str,
        end: str,
    ) -> dict[str, Any]:
        """Behavioral conn.log rollup for one originating host.

        Args:
            host: Originating IP (matched against ``id.orig_h``).
            start: ISO-8601 window start (inclusive).
            end: ISO-8601 window end (exclusive).

        Returns:
            Envelope with totals, distinct peers, per-destination connection
            counts / byte volumes, and long-lived connections (duration >
            ``LONG_LIVED_THRESHOLD_SECONDS``).
        """
        if self.mock_mode:
            return self._mock_connection_summary(host, start, end)
        return await self._real_connection_summary(host, start, end)

    # ----- mock implementations -----

    def _rows_in_window(
        self, log_type: str, start: str | None, end: str | None
    ) -> list[dict[str, Any]]:
        rows = ZEEK_FIXTURE_LOGS.get(log_type, [])
        start_dt = _parse_zeek_timestamp(start) if start else None
        end_dt = _parse_zeek_timestamp(end) if end else None
        out: list[dict[str, Any]] = []
        for row in rows:
            ts = _parse_zeek_timestamp(row.get("ts"))
            if start_dt is not None and ts < start_dt:
                continue
            if end_dt is not None and ts >= end_dt:
                continue
            out.append(row)
        return out

    def _mock_log_search(
        self,
        log_type: str,
        start: str,
        end: str,
        filter_expr: str | None,
        limit: int,
    ) -> dict[str, Any]:
        if log_type not in ZEEK_FIXTURE_LOGS:
            return {
                "status": "unknown_log",
                "is_mock": True,
                "log_type": log_type,
                "message": (
                    f"Mock Zeek search serves only: {sorted(ZEEK_FIXTURE_LOGS)} (got {log_type!r})"
                ),
            }
        literals = [lit.lower() for lit in _filter_literals(filter_expr)]
        matched: list[dict[str, Any]] = []
        for row in self._rows_in_window(log_type, start, end):
            haystack = str(row).lower()
            if all(lit in haystack for lit in literals):
                matched.append(row)
            if len(matched) >= limit:
                break
        return {
            "status": "success",
            "is_mock": True,
            "log_type": log_type,
            "start": start,
            "end": end,
            "filter_expr": filter_expr,
            "applied_literal_filters": literals,
            "total": len(matched),
            "rows": matched,
        }

    def _mock_list_notices(
        self,
        start: str | None,
        end: str | None,
        note_contains: str | None,
        limit: int,
    ) -> dict[str, Any]:
        notices = [
            n
            for n in self._rows_in_window("notice", start, end)
            if note_contains is None or note_contains in str(n.get("note", ""))
        ][:limit]
        return {
            "status": "success",
            "is_mock": True,
            "start": start,
            "end": end,
            "note_contains": note_contains,
            "total": len(notices),
            "notices": notices,
        }

    def _mock_connection_summary(self, host: str, start: str, end: str) -> dict[str, Any]:
        conns = [c for c in self._rows_in_window("conn", start, end) if c.get("id.orig_h") == host]
        if not conns:
            return {
                "status": "not_found",
                "is_mock": True,
                "host": host,
                "message": f"No connections originated by '{host}' in the window",
            }
        dest_counter: Counter[str] = Counter()
        dest_bytes: dict[str, dict[str, int]] = {}
        long_lived: list[dict[str, Any]] = []
        total_orig = 0
        total_resp = 0
        for c in conns:
            dest = f"{c.get('id.resp_h')}:{c.get('id.resp_p')}"
            dest_counter[dest] += 1
            db = dest_bytes.setdefault(dest, {"orig_bytes": 0, "resp_bytes": 0})
            db["orig_bytes"] += int(c.get("orig_bytes") or 0)
            db["resp_bytes"] += int(c.get("resp_bytes") or 0)
            total_orig += int(c.get("orig_bytes") or 0)
            total_resp += int(c.get("resp_bytes") or 0)
            if float(c.get("duration") or 0) > LONG_LIVED_THRESHOLD_SECONDS:
                long_lived.append(
                    {
                        "uid": c.get("uid"),
                        "destination": dest,
                        "duration": c.get("duration"),
                        "orig_bytes": c.get("orig_bytes"),
                    }
                )
        destinations = [
            {
                "destination": dest,
                "connections": count,
                "orig_bytes": dest_bytes[dest]["orig_bytes"],
                "resp_bytes": dest_bytes[dest]["resp_bytes"],
            }
            for dest, count in dest_counter.most_common()
        ]
        return {
            "status": "success",
            "is_mock": True,
            "host": host,
            "start": start,
            "end": end,
            "total_connections": len(conns),
            "distinct_destinations": len(dest_counter),
            "total_orig_bytes": total_orig,
            "total_resp_bytes": total_resp,
            "destinations": destinations,
            "long_lived_connections": long_lived,
            "long_lived_threshold_seconds": LONG_LIVED_THRESHOLD_SECONDS,
        }

    # ----- real implementations (placeholders, fail-safe) -----

    async def _real_log_search(
        self,
        log_type: str,
        start: str,
        end: str,
        filter_expr: str | None,
        limit: int,
    ) -> dict[str, Any]:
        token = self._get_api_token()
        if not token or token.startswith("<unresolved:"):
            logger.warning(
                "zeek: live-mode log search refused — no API token (%s)",
                _redact_secret(token),
            )
            raise NotImplementedError(
                "Zeek/Corelight live mode requires a resolvable API token "
                "(wire ${secret:vault:zeek/corelight_api_token} or set "
                "BTAGENT_ZEEK_API_TOKEN)."
            )
        raise NotImplementedError("Zeek live log_search not yet implemented")

    async def _real_list_notices(
        self,
        start: str | None,
        end: str | None,
        note_contains: str | None,
        limit: int,
    ) -> dict[str, Any]:
        token = self._get_api_token()
        if not token or token.startswith("<unresolved:"):
            logger.warning(
                "zeek: live-mode notice list refused — no API token (%s)",
                _redact_secret(token),
            )
            raise NotImplementedError("Zeek/Corelight live mode requires a resolvable API token")
        raise NotImplementedError("Zeek live list_notices not yet implemented")

    async def _real_connection_summary(self, host: str, start: str, end: str) -> dict[str, Any]:
        token = self._get_api_token()
        if not token or token.startswith("<unresolved:"):
            raise NotImplementedError("Zeek/Corelight live mode requires a resolvable API token")
        raise NotImplementedError("Zeek live connection_summary not yet implemented")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "zeek_log_search",
                "description": (
                    "Search one Zeek / Corelight log stream (conn | dns | ssl "
                    "| notice) for a time window. Quoted literals in "
                    "filter_expr narrow results. Native Zeek field names "
                    "(ts, uid, id.orig_h, …)."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "log_type": {
                            "type": "string",
                            "enum": ["conn", "dns", "ssl", "notice"],
                            "description": "Zeek log stream",
                        },
                        "start": {"type": "string", "description": "ISO-8601 start (inclusive)"},
                        "end": {"type": "string", "description": "ISO-8601 end (exclusive)"},
                        "filter_expr": {
                            "type": "string",
                            "description": "Optional filter; quoted literals narrow rows",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max rows to return",
                            "default": 100,
                        },
                    },
                    "required": ["log_type", "start", "end"],
                },
            },
            {
                "name": "zeek_list_notices",
                "description": (
                    "List Zeek notice.log detections (built-in + Corelight "
                    "packages: invalid certs, scans, DNS tunneling, …) with "
                    "an optional note-type substring filter."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "start": {
                            "type": "string",
                            "description": "Optional ISO-8601 start (inclusive)",
                        },
                        "end": {
                            "type": "string",
                            "description": "Optional ISO-8601 end (exclusive)",
                        },
                        "note_contains": {
                            "type": "string",
                            "description": "Optional substring over the note type",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max notices to return",
                            "default": 100,
                        },
                    },
                },
            },
            {
                "name": "zeek_connection_summary",
                "description": (
                    "Behavioral conn.log rollup for one originating host: "
                    "totals, distinct peers, per-destination connection "
                    "counts / byte volumes, long-lived connections — the "
                    "beaconing / exfiltration hunting signal."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "Originating IP (id.orig_h)"},
                        "start": {"type": "string", "description": "ISO-8601 start (inclusive)"},
                        "end": {"type": "string", "description": "ISO-8601 end (exclusive)"},
                    },
                    "required": ["host", "start", "end"],
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances (parity with sibling connectors)
# ---------------------------------------------------------------------------
_server = ZeekMCPServer()


@tool
async def zeek_log_search(
    log_type: str,
    start: str,
    end: str,
    filter_expr: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Search one Zeek / Corelight log stream (conn | dns | ssl | notice).

    Args:
        log_type: Zeek log stream (conn | dns | ssl | notice).
        start: ISO-8601 window start (inclusive).
        end: ISO-8601 window end (exclusive).
        filter_expr: Optional filter; quoted literals narrow rows.
        limit: Max rows to return.
    """
    return await _server.zeek_log_search(log_type, start, end, filter_expr, limit)


@tool
async def zeek_list_notices(
    start: str | None = None,
    end: str | None = None,
    note_contains: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """List Zeek notice.log detections.

    Args:
        start: Optional ISO-8601 window start (inclusive).
        end: Optional ISO-8601 window end (exclusive).
        note_contains: Optional substring over the note type.
        limit: Max notices to return.
    """
    return await _server.zeek_list_notices(start, end, note_contains, limit)


@tool
async def zeek_connection_summary(
    host: str,
    start: str,
    end: str,
) -> dict[str, Any]:
    """Behavioral conn.log rollup for one originating host.

    Args:
        host: Originating IP (matched against id.orig_h).
        start: ISO-8601 window start (inclusive).
        end: ISO-8601 window end (exclusive).
    """
    return await _server.zeek_connection_summary(host, start, end)
