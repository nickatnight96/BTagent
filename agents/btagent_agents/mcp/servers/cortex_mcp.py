"""Palo Alto Cortex XDR MCP server connector — Tier-2 slice (#100).

XDR-class endpoint + network telemetry with a query language (XQL), an
incident lifecycle, and endpoint isolation; the second Tier-2 connector,
built in the modern style (fixtures module, lazy ``${secret:…}`` resolution,
guarded live mode, full contract tests) and mirroring
:mod:`btagent_agents.mcp.servers.sentinelone_mcp`.

Capabilities:

- ``cortex_xql_query(query, from_date, to_date, limit=100)`` — run an XQL
  (Cortex Query Language) event search. The mock applies conjunctive
  quoted-literal narrowing over one typed event stream (see below).
- ``cortex_list_incidents(status=None, severity=None, limit=50)`` —
  ``/incidents``-style objects with status / severity filters.
- ``cortex_get_endpoint(hostname)`` — endpoint record (connection status,
  isolation state, OS, last-seen).
- ``cortex_isolate_endpoint(endpoint_id, action="isolate")`` — endpoint
  isolation (isolate / unisolate). **Requires HITL approval** (parity with
  ``s1_mitigate_threat`` / ``mde_isolate_machine`` / ``cs_isolate_host``; the
  HITLHook gates it in the execution path).

Mock XQL semantics (documented so tests and prompts agree)
----------------------------------------------------------
Real XQL is not interpreted. The Cortex datalake is one event stream (no
``dataset`` routing): the mock keeps rows containing **every** double-quoted
string literal in the query (case-insensitive substring over the row's
JSON), then applies the ``from_date``/``to_date`` window on ``event_time``
and the row limit. ``action_process_image_name = "updater.exe" and
action_remote_ip = "45.77.10.204"`` therefore narrows exactly as an analyst
would expect; arbitrary operators degrade gracefully to "no extra filtering".

Secret hygiene mirrors the sibling connectors: the Cortex API key is resolved
lazily, never logged (fingerprint only via :func:`_redact_secret`), and never
returned in MCP envelopes; ``repr()`` omits it.
"""

from __future__ import annotations

import logging
import os
import re
from datetime import UTC, datetime
from typing import Any

from btagent_shared.utils.secrets import resolve_secret
from langchain_core.tools import tool

from btagent_agents.mcp.servers._cortex_fixtures import (
    CORTEX_FIXTURE_ENDPOINTS,
    CORTEX_FIXTURE_INCIDENTS,
    CORTEX_FIXTURE_XQL_EVENTS,
)

logger = logging.getLogger("btagent.mcp.servers.cortex")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"

ISOLATION_ACTIONS: tuple[str, ...] = ("isolate", "unisolate")

_QUOTED_LITERAL = re.compile(r'"([^"]+)"')


def _xql_literals(query: str) -> list[str]:
    """Extract the double-quoted string literals from an XQL query."""
    return _QUOTED_LITERAL.findall(query or "")


def _parse_timestamp(value: str | None) -> datetime:
    """Parse an ISO-8601 timestamp into an aware ``datetime`` (epoch fallback)."""
    if not value:
        return datetime.fromtimestamp(0, tz=UTC)
    raw = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        logger.debug("cortex: failed to parse timestamp %r", value)
        return datetime.fromtimestamp(0, tz=UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


# ---------------------------------------------------------------------------
# Secret-redaction helper for log lines local to this module
# ---------------------------------------------------------------------------
def _redact_secret(secret: str) -> str:
    """Return a safe-to-log fingerprint of the Cortex API key.

    Never returns the raw secret; a short suffix fingerprint is emitted only
    when the secret is long enough for the suffix to be non-identifying.
    """
    if not secret or len(secret) < 12:
        return "[redacted]"
    return f"[redacted:cortex-api-key:…{secret[-4:]}]"


# ---------------------------------------------------------------------------
# Cortex XDR MCP server class
# ---------------------------------------------------------------------------
class CortexXDRMCPServer:
    """Cortex XDR MCP connector with mock and real modes.

    Default mode is mock (``BTAGENT_MOCK_CONNECTORS=true``) — the connector
    never calls the Cortex API unless explicitly opted out AND an API key
    resolves. The mock path is what CI exercises; live mode is a guarded
    placeholder.
    """

    server_id: str = "cortex"

    DEFAULT_API_KEY_REF: str = "${secret:vault:cortex/api_key}"
    DEFAULT_API_KEY_ID_REF: str = "${env:BTAGENT_CORTEX_API_KEY_ID}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        api_base_url: str | None = None,
        api_key_ref: str | None = None,
        api_key_id_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self.api_base_url: str = (
            api_base_url
            or os.getenv("BTAGENT_CORTEX_API_URL")
            or "https://api-acme.xdr.us.paloaltonetworks.com"
        )
        self._api_key_ref: str = api_key_ref or self.DEFAULT_API_KEY_REF
        self._api_key_id_ref: str = api_key_id_ref or self.DEFAULT_API_KEY_ID_REF

    # ----- safety: never put the key in repr/str -----

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"CortexXDRMCPServer(server_id={self.server_id!r}, "
            f"api_base_url={self.api_base_url!r}, mock_mode={self.mock_mode!r})"
        )

    # ----- lazy secret resolution -----

    def _get_api_key(self) -> str:
        """Resolve the Cortex API key lazily from the configured ref."""
        resolved: str = resolve_secret(self._api_key_ref)
        return resolved

    # ----- tools -----

    async def cortex_xql_query(
        self,
        query: str,
        from_date: str,
        to_date: str,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Run an XQL (Cortex Query Language) event search.

        Args:
            query: XQL query text; quoted literals narrow the mock.
            from_date: ISO-8601 window start (inclusive).
            to_date: ISO-8601 window end (exclusive).
            limit: Max events to return.

        Returns:
            Envelope with the matched events and the mock's applied literal
            filters (see the module docstring for the mock XQL semantics).
        """
        if self.mock_mode:
            return self._mock_xql_query(query, from_date, to_date, limit)
        return await self._real_xql_query(query, from_date, to_date, limit)

    async def cortex_list_incidents(
        self,
        status: str | None = None,
        severity: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List Cortex XDR incidents.

        Args:
            status: Optional exact filter (new|under_investigation|resolved).
            severity: Optional exact filter (informational|low|medium|high|critical).
            limit: Max incidents to return.

        Returns:
            Envelope with incident objects (severity, status, host join,
            MITRE mapping, alert count).
        """
        if self.mock_mode:
            return self._mock_list_incidents(status, severity, limit)
        return await self._real_list_incidents(status, severity, limit)

    async def cortex_get_endpoint(self, hostname: str) -> dict[str, Any]:
        """Get a Cortex XDR endpoint record.

        Args:
            hostname: The endpoint's name.

        Returns:
            Envelope with the endpoint record (connection status, isolation
            state, OS, last-seen) or a ``not_found`` status.
        """
        if self.mock_mode:
            return self._mock_get_endpoint(hostname)
        return await self._real_get_endpoint(hostname)

    async def cortex_isolate_endpoint(
        self,
        endpoint_id: str,
        action: str = "isolate",
    ) -> dict[str, Any]:
        """Isolate (or unisolate) a Cortex XDR endpoint.

        IMPORTANT: This is a containment action that requires HITL approval
        before execution (the HITLHook gates it in the execution path).

        Args:
            endpoint_id: The endpoint's id.
            action: isolate | unisolate.

        Returns:
            Isolation action result; ``requires_hitl`` is always True.
        """
        if self.mock_mode:
            return self._mock_isolate_endpoint(endpoint_id, action)
        return await self._real_isolate_endpoint(endpoint_id, action)

    # ----- mock implementations -----

    def _mock_xql_query(
        self, query: str, from_date: str, to_date: str, limit: int
    ) -> dict[str, Any]:
        start_dt = _parse_timestamp(from_date)
        end_dt = _parse_timestamp(to_date)
        literals = [lit.lower() for lit in _xql_literals(query)]
        matched: list[dict[str, Any]] = []
        for row in CORTEX_FIXTURE_XQL_EVENTS:
            ts = _parse_timestamp(row.get("event_time"))
            if ts < start_dt or ts >= end_dt:
                continue
            haystack = str(row).lower()
            if all(lit in haystack for lit in literals):
                matched.append(row)
            if len(matched) >= limit:
                break
        return {
            "status": "success",
            "is_mock": True,
            "query": query,
            "from_date": from_date,
            "to_date": to_date,
            "applied_literal_filters": literals,
            "total": len(matched),
            "events": matched,
        }

    def _mock_list_incidents(
        self, status: str | None, severity: str | None, limit: int
    ) -> dict[str, Any]:
        incidents = [
            inc
            for inc in CORTEX_FIXTURE_INCIDENTS
            if (status is None or inc.get("status") == status)
            and (severity is None or inc.get("severity") == severity)
        ][:limit]
        return {
            "status": "success",
            "is_mock": True,
            "incident_status": status,
            "severity": severity,
            "total": len(incidents),
            "incidents": incidents,
        }

    def _mock_get_endpoint(self, hostname: str) -> dict[str, Any]:
        endpoint = CORTEX_FIXTURE_ENDPOINTS.get(hostname)
        if endpoint is None:
            return {
                "status": "not_found",
                "is_mock": True,
                "message": f"Endpoint '{hostname}' not found in Cortex XDR",
            }
        return {"status": "success", "is_mock": True, "endpoint": endpoint}

    def _mock_isolate_endpoint(self, endpoint_id: str, action: str) -> dict[str, Any]:
        endpoint = next(
            (e for e in CORTEX_FIXTURE_ENDPOINTS.values() if e["endpoint_id"] == endpoint_id),
            None,
        )
        if endpoint is None:
            return {
                "status": "error",
                "is_mock": True,
                "message": f"Endpoint '{endpoint_id}' not found",
            }
        if action not in ISOLATION_ACTIONS:
            return {
                "status": "error",
                "is_mock": True,
                "message": f"Invalid action {action!r} ({'|'.join(ISOLATION_ACTIONS)})",
            }
        new_state = "AGENT_ISOLATED" if action == "isolate" else "AGENT_UNISOLATED"
        return {
            "status": "success",
            "is_mock": True,
            "action": action,
            "endpoint_id": endpoint_id,
            "endpoint_name": endpoint["endpoint_name"],
            "isolation_status": new_state,
            "message": (
                f"Isolation action '{action}' applied to endpoint {endpoint['endpoint_name']}."
            ),
            "requires_hitl": True,
        }

    # ----- real implementations (placeholders, fail-safe) -----

    async def _real_xql_query(
        self, query: str, from_date: str, to_date: str, limit: int
    ) -> dict[str, Any]:
        key = self._get_api_key()
        if not key or key.startswith("<unresolved:"):
            logger.warning(
                "cortex: live-mode XQL query refused — no API key (%s)",
                _redact_secret(key),
            )
            raise NotImplementedError(
                "Cortex XDR live mode requires a resolvable API key "
                "(wire ${secret:vault:cortex/api_key} or set BTAGENT_CORTEX_API_KEY)."
            )
        raise NotImplementedError("Cortex XDR live xql_query not yet implemented")

    async def _real_list_incidents(
        self, status: str | None, severity: str | None, limit: int
    ) -> dict[str, Any]:
        key = self._get_api_key()
        if not key or key.startswith("<unresolved:"):
            logger.warning(
                "cortex: live-mode incident list refused — no API key (%s)",
                _redact_secret(key),
            )
            raise NotImplementedError("Cortex XDR live mode requires a resolvable API key")
        raise NotImplementedError("Cortex XDR live list_incidents not yet implemented")

    async def _real_get_endpoint(self, hostname: str) -> dict[str, Any]:
        key = self._get_api_key()
        if not key or key.startswith("<unresolved:"):
            raise NotImplementedError("Cortex XDR live mode requires a resolvable API key")
        raise NotImplementedError("Cortex XDR live get_endpoint not yet implemented")

    async def _real_isolate_endpoint(self, endpoint_id: str, action: str) -> dict[str, Any]:
        key = self._get_api_key()
        if not key or key.startswith("<unresolved:"):
            raise NotImplementedError("Cortex XDR live mode requires a resolvable API key")
        raise NotImplementedError("Cortex XDR live isolate_endpoint not yet implemented")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "cortex_xql_query",
                "description": (
                    "Run a Cortex XDR XQL event search over process / network "
                    "/ DNS telemetry for a time window. Quoted literals narrow "
                    "results."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "XQL query text"},
                        "from_date": {
                            "type": "string",
                            "description": "ISO-8601 window start (inclusive)",
                        },
                        "to_date": {
                            "type": "string",
                            "description": "ISO-8601 window end (exclusive)",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max events to return",
                            "default": 100,
                        },
                    },
                    "required": ["query", "from_date", "to_date"],
                },
            },
            {
                "name": "cortex_list_incidents",
                "description": (
                    "List Cortex XDR incidents with status and severity "
                    "filters. Incidents carry the host join, MITRE mapping, "
                    "and alert count."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "status": {
                            "type": "string",
                            "enum": ["new", "under_investigation", "resolved"],
                            "description": "Optional exact incident status",
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["informational", "low", "medium", "high", "critical"],
                            "description": "Optional exact severity",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max incidents to return",
                            "default": 50,
                        },
                    },
                },
            },
            {
                "name": "cortex_get_endpoint",
                "description": (
                    "Get a Cortex XDR endpoint record: connection status, "
                    "isolation state, OS, last-seen, logged-in users."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hostname": {"type": "string", "description": "Endpoint name"},
                    },
                    "required": ["hostname"],
                },
            },
            {
                "name": "cortex_isolate_endpoint",
                "description": (
                    "Isolate or unisolate a Cortex XDR endpoint. REQUIRES HITL APPROVAL."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "endpoint_id": {"type": "string", "description": "Endpoint id"},
                        "action": {
                            "type": "string",
                            "enum": list(ISOLATION_ACTIONS),
                            "default": "isolate",
                        },
                    },
                    "required": ["endpoint_id"],
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances (parity with sibling connectors)
# ---------------------------------------------------------------------------
_server = CortexXDRMCPServer()


@tool
async def cortex_xql_query(
    query: str,
    from_date: str,
    to_date: str,
    limit: int = 100,
) -> dict[str, Any]:
    """Run a Cortex XDR XQL event search.

    Args:
        query: XQL query text; quoted literals narrow results.
        from_date: ISO-8601 window start (inclusive).
        to_date: ISO-8601 window end (exclusive).
        limit: Max events to return.
    """
    return await _server.cortex_xql_query(query, from_date, to_date, limit)


@tool
async def cortex_list_incidents(
    status: str | None = None,
    severity: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """List Cortex XDR incidents.

    Args:
        status: Optional exact filter (new|under_investigation|resolved).
        severity: Optional exact filter (informational|low|medium|high|critical).
        limit: Max incidents to return.
    """
    return await _server.cortex_list_incidents(status, severity, limit)


@tool
async def cortex_get_endpoint(hostname: str) -> dict[str, Any]:
    """Get a Cortex XDR endpoint record.

    Args:
        hostname: The endpoint's name.
    """
    return await _server.cortex_get_endpoint(hostname)


@tool
async def cortex_isolate_endpoint(
    endpoint_id: str,
    action: str = "isolate",
) -> dict[str, Any]:
    """Isolate or unisolate a Cortex XDR endpoint. Requires HITL approval.

    Args:
        endpoint_id: The endpoint's id.
        action: isolate | unisolate.
    """
    return await _server.cortex_isolate_endpoint(endpoint_id, action)
