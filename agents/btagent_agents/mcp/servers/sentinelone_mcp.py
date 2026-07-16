"""SentinelOne MCP server connector — Tier-1 slice (#100).

Top-3 EDR with XDR-class telemetry; third EDR connector overall and the
second built in the modern Tier-1 style (fixtures module, lazy ``${secret:…}``
resolution, guarded live mode, full contract tests).

Capabilities:

- ``s1_deep_visibility_query(query, from_date, to_date, limit=100)`` — run a
  Deep Visibility (S1QL) event search. The mock applies conjunctive
  quoted-literal narrowing over one typed event stream (see below).
- ``s1_list_threats(incident_status=None, confidence=None, limit=50)`` —
  ``/threats``-style objects with incident / confidence filters.
- ``s1_get_agent(hostname)`` — agent record (network status, infected flag,
  mitigation mode).
- ``s1_mitigate_threat(threat_id, action="quarantine")`` — threat mitigation
  (kill / quarantine / remediate / rollback-remediation). **Requires HITL
  approval** (parity with ``cs_isolate_host`` / ``mde_isolate_machine``; the
  HITLHook gates it in the execution path).

Mock S1QL semantics (documented so tests and prompts agree)
-----------------------------------------------------------
Real S1QL is not interpreted. Deep Visibility is one event stream (no table
routing): the mock keeps rows containing **every** double-quoted string
literal in the query (case-insensitive substring over the row's JSON), then
applies the ``from_date``/``to_date`` window on ``eventTime`` and the row
limit. ``EventType = "IP Connect" AND DstIP = "198.51.100.99"`` therefore
narrows exactly as an analyst would expect; arbitrary operators degrade
gracefully to "no extra filtering".

Secret hygiene mirrors the sibling connectors: the console API token is
resolved lazily, never logged (fingerprint only via :func:`_redact_secret`),
and never returned in MCP envelopes; ``repr()`` omits it.
"""

from __future__ import annotations

import logging
import os
import re
from datetime import UTC, datetime
from typing import Any

from btagent_shared.utils.secrets import resolve_secret
from langchain_core.tools import tool

from btagent_agents.mcp.servers._sentinelone_fixtures import (
    S1_FIXTURE_AGENTS,
    S1_FIXTURE_DV_EVENTS,
    S1_FIXTURE_THREATS,
)

logger = logging.getLogger("btagent.mcp.servers.sentinelone")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"

MITIGATION_ACTIONS: tuple[str, ...] = ("kill", "quarantine", "remediate", "rollback-remediation")

_QUOTED_LITERAL = re.compile(r'"([^"]+)"')


def _s1ql_literals(query: str) -> list[str]:
    """Extract the double-quoted string literals from an S1QL query."""
    return _QUOTED_LITERAL.findall(query or "")


def _parse_s1_timestamp(value: str | None) -> datetime:
    """Parse an ISO-8601 timestamp into an aware ``datetime`` (epoch fallback)."""
    if not value:
        return datetime.fromtimestamp(0, tz=UTC)
    raw = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        logger.debug("sentinelone: failed to parse timestamp %r", value)
        return datetime.fromtimestamp(0, tz=UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


# ---------------------------------------------------------------------------
# Secret-redaction helper for log lines local to this module
# ---------------------------------------------------------------------------
def _redact_secret(secret: str) -> str:
    """Return a safe-to-log fingerprint of the console API token.

    Never returns the raw secret; a short suffix fingerprint is emitted only
    when the secret is long enough for the suffix to be non-identifying.
    """
    if not secret or len(secret) < 12:
        return "[redacted]"
    return f"[redacted:s1-api-token:…{secret[-4:]}]"


# ---------------------------------------------------------------------------
# SentinelOne MCP server class
# ---------------------------------------------------------------------------
class SentinelOneMCPServer:
    """SentinelOne MCP connector with mock and real modes.

    Default mode is mock (``BTAGENT_MOCK_CONNECTORS=true``) — the connector
    never calls the Management API unless explicitly opted out AND an API
    token resolves. The mock path is what CI exercises; live mode is a
    guarded placeholder.
    """

    server_id: str = "sentinelone"

    DEFAULT_API_TOKEN_REF: str = "${secret:vault:sentinelone/api_token}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        console_base_url: str | None = None,
        api_token_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self.console_base_url: str = (
            console_base_url
            or os.getenv("BTAGENT_S1_CONSOLE_URL")
            or "https://usea1.sentinelone.net"
        )
        self._api_token_ref: str = api_token_ref or self.DEFAULT_API_TOKEN_REF

    # ----- safety: never put the token in repr/str -----

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"SentinelOneMCPServer(server_id={self.server_id!r}, "
            f"console_base_url={self.console_base_url!r}, mock_mode={self.mock_mode!r})"
        )

    # ----- lazy secret resolution -----

    def _get_api_token(self) -> str:
        """Resolve the console API token lazily from the configured ref."""
        resolved: str = resolve_secret(self._api_token_ref)
        return resolved

    # ----- tools -----

    async def s1_deep_visibility_query(
        self,
        query: str,
        from_date: str,
        to_date: str,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Run a Deep Visibility (S1QL) event search.

        Args:
            query: S1QL query text; quoted literals narrow the mock.
            from_date: ISO-8601 window start (inclusive).
            to_date: ISO-8601 window end (exclusive).
            limit: Max events to return.

        Returns:
            Envelope with the matched events and the mock's applied literal
            filters (see the module docstring for the mock S1QL semantics).
        """
        if self.mock_mode:
            return self._mock_deep_visibility_query(query, from_date, to_date, limit)
        return await self._real_deep_visibility_query(query, from_date, to_date, limit)

    async def s1_list_threats(
        self,
        incident_status: str | None = None,
        confidence: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List SentinelOne threats.

        Args:
            incident_status: Optional exact filter
                (unresolved|in_progress|resolved).
            confidence: Optional exact filter (malicious|suspicious).
            limit: Max threats to return.

        Returns:
            Envelope with threat objects (classification, MITRE mapping,
            mitigation lifecycle, agent join info).
        """
        if self.mock_mode:
            return self._mock_list_threats(incident_status, confidence, limit)
        return await self._real_list_threats(incident_status, confidence, limit)

    async def s1_get_agent(self, hostname: str) -> dict[str, Any]:
        """Get a SentinelOne agent record.

        Args:
            hostname: The endpoint's computer name.

        Returns:
            Envelope with the agent record (network status, infected flag,
            mitigation mode) or a ``not_found`` status.
        """
        if self.mock_mode:
            return self._mock_get_agent(hostname)
        return await self._real_get_agent(hostname)

    async def s1_mitigate_threat(
        self,
        threat_id: str,
        action: str = "quarantine",
    ) -> dict[str, Any]:
        """Apply a mitigation action to a threat.

        IMPORTANT: This is a containment action that requires HITL approval
        before execution (the HITLHook gates it in the execution path).

        Args:
            threat_id: The threat's id.
            action: kill | quarantine | remediate | rollback-remediation.

        Returns:
            Mitigation action result; ``requires_hitl`` is always True.
        """
        if self.mock_mode:
            return self._mock_mitigate_threat(threat_id, action)
        return await self._real_mitigate_threat(threat_id, action)

    # ----- mock implementations -----

    def _mock_deep_visibility_query(
        self, query: str, from_date: str, to_date: str, limit: int
    ) -> dict[str, Any]:
        start_dt = _parse_s1_timestamp(from_date)
        end_dt = _parse_s1_timestamp(to_date)
        literals = [lit.lower() for lit in _s1ql_literals(query)]
        matched: list[dict[str, Any]] = []
        for row in S1_FIXTURE_DV_EVENTS:
            ts = _parse_s1_timestamp(row.get("eventTime"))
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

    def _mock_list_threats(
        self, incident_status: str | None, confidence: str | None, limit: int
    ) -> dict[str, Any]:
        threats = [
            t
            for t in S1_FIXTURE_THREATS
            if (incident_status is None or t["threatInfo"].get("incidentStatus") == incident_status)
            and (confidence is None or t["threatInfo"].get("confidenceLevel") == confidence)
        ][:limit]
        return {
            "status": "success",
            "is_mock": True,
            "incident_status": incident_status,
            "confidence": confidence,
            "total": len(threats),
            "threats": threats,
        }

    def _mock_get_agent(self, hostname: str) -> dict[str, Any]:
        agent = S1_FIXTURE_AGENTS.get(hostname)
        if agent is None:
            return {
                "status": "not_found",
                "is_mock": True,
                "message": f"Agent '{hostname}' not found in SentinelOne",
            }
        return {"status": "success", "is_mock": True, "agent": agent}

    def _mock_mitigate_threat(self, threat_id: str, action: str) -> dict[str, Any]:
        threat = next((t for t in S1_FIXTURE_THREATS if t["id"] == threat_id), None)
        if threat is None:
            return {
                "status": "error",
                "is_mock": True,
                "message": f"Threat '{threat_id}' not found",
            }
        if action not in MITIGATION_ACTIONS:
            return {
                "status": "error",
                "is_mock": True,
                "message": f"Invalid action {action!r} ({'|'.join(MITIGATION_ACTIONS)})",
            }
        info = threat["threatInfo"]
        return {
            "status": "success",
            "is_mock": True,
            "action": action,
            "threat_id": threat_id,
            "threat_name": info["threatName"],
            "hostname": threat["agentRealtimeInfo"]["agentComputerName"],
            "mitigation_status": "mitigated",
            "message": (
                f"Mitigation '{action}' applied to threat '{info['threatName']}' on "
                f"{threat['agentRealtimeInfo']['agentComputerName']}."
            ),
            "requires_hitl": True,
        }

    # ----- real implementations (placeholders, fail-safe) -----

    async def _real_deep_visibility_query(
        self, query: str, from_date: str, to_date: str, limit: int
    ) -> dict[str, Any]:
        token = self._get_api_token()
        if not token or token.startswith("<unresolved:"):
            logger.warning(
                "sentinelone: live-mode Deep Visibility query refused — no API token (%s)",
                _redact_secret(token),
            )
            raise NotImplementedError(
                "SentinelOne live mode requires a resolvable console API token "
                "(wire ${secret:vault:sentinelone/api_token} or set "
                "BTAGENT_S1_API_TOKEN)."
            )
        raise NotImplementedError("SentinelOne live deep_visibility_query not yet implemented")

    async def _real_list_threats(
        self, incident_status: str | None, confidence: str | None, limit: int
    ) -> dict[str, Any]:
        token = self._get_api_token()
        if not token or token.startswith("<unresolved:"):
            logger.warning(
                "sentinelone: live-mode threat list refused — no API token (%s)",
                _redact_secret(token),
            )
            raise NotImplementedError(
                "SentinelOne live mode requires a resolvable console API token"
            )
        raise NotImplementedError("SentinelOne live list_threats not yet implemented")

    async def _real_get_agent(self, hostname: str) -> dict[str, Any]:
        token = self._get_api_token()
        if not token or token.startswith("<unresolved:"):
            raise NotImplementedError(
                "SentinelOne live mode requires a resolvable console API token"
            )
        raise NotImplementedError("SentinelOne live get_agent not yet implemented")

    async def _real_mitigate_threat(self, threat_id: str, action: str) -> dict[str, Any]:
        token = self._get_api_token()
        if not token or token.startswith("<unresolved:"):
            raise NotImplementedError(
                "SentinelOne live mode requires a resolvable console API token"
            )
        raise NotImplementedError("SentinelOne live mitigate_threat not yet implemented")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "s1_deep_visibility_query",
                "description": (
                    "Run a SentinelOne Deep Visibility (S1QL) event search "
                    "over process / network / DNS telemetry for a time "
                    "window. Quoted literals narrow results."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "S1QL query text"},
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
                "name": "s1_list_threats",
                "description": (
                    "List SentinelOne threats with incident-status and "
                    "confidence filters. Threats carry classification, MITRE "
                    "mapping, and the mitigation lifecycle."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "incident_status": {
                            "type": "string",
                            "enum": ["unresolved", "in_progress", "resolved"],
                            "description": "Optional exact incident status",
                        },
                        "confidence": {
                            "type": "string",
                            "enum": ["malicious", "suspicious"],
                            "description": "Optional exact confidence level",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max threats to return",
                            "default": 50,
                        },
                    },
                },
            },
            {
                "name": "s1_get_agent",
                "description": (
                    "Get a SentinelOne agent record: network status, infected "
                    "flag, mitigation mode, logged-in user."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hostname": {"type": "string", "description": "Endpoint computer name"},
                    },
                    "required": ["hostname"],
                },
            },
            {
                "name": "s1_mitigate_threat",
                "description": (
                    "Apply a SentinelOne mitigation action (kill | quarantine "
                    "| remediate | rollback-remediation) to a threat. "
                    "REQUIRES HITL APPROVAL."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "threat_id": {"type": "string", "description": "Threat id"},
                        "action": {
                            "type": "string",
                            "enum": list(MITIGATION_ACTIONS),
                            "default": "quarantine",
                        },
                    },
                    "required": ["threat_id"],
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances (parity with sibling connectors)
# ---------------------------------------------------------------------------
_server = SentinelOneMCPServer()


@tool
async def s1_deep_visibility_query(
    query: str,
    from_date: str,
    to_date: str,
    limit: int = 100,
) -> dict[str, Any]:
    """Run a SentinelOne Deep Visibility (S1QL) event search.

    Args:
        query: S1QL query text; quoted literals narrow results.
        from_date: ISO-8601 window start (inclusive).
        to_date: ISO-8601 window end (exclusive).
        limit: Max events to return.
    """
    return await _server.s1_deep_visibility_query(query, from_date, to_date, limit)


@tool
async def s1_list_threats(
    incident_status: str | None = None,
    confidence: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """List SentinelOne threats.

    Args:
        incident_status: Optional exact filter (unresolved|in_progress|resolved).
        confidence: Optional exact filter (malicious|suspicious).
        limit: Max threats to return.
    """
    return await _server.s1_list_threats(incident_status, confidence, limit)


@tool
async def s1_get_agent(hostname: str) -> dict[str, Any]:
    """Get a SentinelOne agent record.

    Args:
        hostname: The endpoint's computer name.
    """
    return await _server.s1_get_agent(hostname)


@tool
async def s1_mitigate_threat(
    threat_id: str,
    action: str = "quarantine",
) -> dict[str, Any]:
    """Apply a SentinelOne mitigation action to a threat. Requires HITL approval.

    Args:
        threat_id: The threat's id.
        action: kill | quarantine | remediate | rollback-remediation.
    """
    return await _server.s1_mitigate_threat(threat_id, action)
