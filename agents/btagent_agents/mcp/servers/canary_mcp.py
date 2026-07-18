"""Thinkst Canary (deception) MCP server connector — Tier-2 slice (#100).

First deception / honeypot connector — the highest-fidelity signal class in
the fleet. A Thinkst Canary (a honeypot device) or Canarytoken (a planted
decoy credential / file / URL) only ever fires when something interacts with a
resource that has no legitimate use, so every incident is a near-zero-false-
positive intruder signal. Built in the modern read-only style (fixtures
module, lazy ``${secret:…}`` resolution, guarded live mode, full contract
tests) and mirroring :mod:`btagent_agents.mcp.servers.vectra_mcp` — no
mutation / containment capability, therefore no HITL-gated tool.

Capabilities:

- ``canary_list_incidents(acknowledged=None, incident_type_contains=None,
  limit=50)`` — triggered incidents (canarytoken use, port scans, SMB/SSH/HTTP
  interactions) with an acknowledged filter and an incident-type substring.
- ``canary_list_devices(kind=None, limit=50)`` — the deployed canary + token
  inventory (kind, location, live flag, last-triggered).
- ``canary_incident_summary(src_host)`` — per-attacker-IP rollup: which
  canaries/tokens the IP tripped, incident types, and the movement across the
  deception grid — the "one intruder, N decoys" triage signal (mirrors
  ``aws_cloudtrail_principal_summary``).

Secret hygiene mirrors the sibling connectors: the Canary Console API token is
resolved lazily, never logged (fingerprint only via :func:`_redact_secret`),
and never returned in MCP envelopes; ``repr()`` omits it.
"""

from __future__ import annotations

import logging
import os
from collections import Counter
from typing import Any

from btagent_shared.utils.secrets import resolve_secret
from langchain_core.tools import tool

from btagent_agents.mcp.servers._canary_fixtures import (
    CANARY_FIXTURE_DEVICES,
    CANARY_FIXTURE_INCIDENTS,
)

logger = logging.getLogger("btagent.mcp.servers.canary")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Secret-redaction helper for log lines local to this module
# ---------------------------------------------------------------------------
def _redact_secret(secret: str) -> str:
    """Return a safe-to-log fingerprint of the Canary Console API token.

    Never returns the raw secret; a short suffix fingerprint is emitted only
    when the secret is long enough for the suffix to be non-identifying.
    """
    if not secret or len(secret) < 12:
        return "[redacted]"
    return f"[redacted:canary-api-token:…{secret[-4:]}]"


# ---------------------------------------------------------------------------
# Thinkst Canary MCP server class
# ---------------------------------------------------------------------------
class CanaryMCPServer:
    """Thinkst Canary MCP connector with mock and real modes.

    Default mode is mock (``BTAGENT_MOCK_CONNECTORS=true``) — the connector
    never calls the Canary Console unless explicitly opted out AND an API
    token resolves. The mock path is what CI exercises; live mode is a guarded
    placeholder.
    """

    server_id: str = "canary"

    DEFAULT_API_TOKEN_REF: str = "${secret:vault:canary/api_token}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        console_url: str | None = None,
        api_token_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self.console_url: str = (
            console_url or os.getenv("BTAGENT_CANARY_CONSOLE_URL") or "https://acme.canary.tools"
        )
        self._api_token_ref: str = api_token_ref or self.DEFAULT_API_TOKEN_REF

    # ----- safety: never put the token in repr/str -----

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"CanaryMCPServer(server_id={self.server_id!r}, "
            f"console_url={self.console_url!r}, mock_mode={self.mock_mode!r})"
        )

    # ----- lazy secret resolution -----

    def _get_api_token(self) -> str:
        """Resolve the Canary Console API token lazily from the configured ref."""
        resolved: str = resolve_secret(self._api_token_ref)
        return resolved

    # ----- tools -----

    async def canary_list_incidents(
        self,
        acknowledged: bool | None = None,
        incident_type_contains: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List triggered Canary incidents.

        Args:
            acknowledged: Optional filter on the acknowledged flag.
            incident_type_contains: Optional substring over the incident type.
            limit: Max incidents to return.

        Returns:
            Envelope with the matched incident objects. Every incident is a
            high-fidelity intruder signal.
        """
        if self.mock_mode:
            return self._mock_list_incidents(acknowledged, incident_type_contains, limit)
        return await self._real_list_incidents(acknowledged, incident_type_contains, limit)

    async def canary_list_devices(
        self,
        kind: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List the deployed Canary + Canarytoken inventory.

        Args:
            kind: Optional exact filter (canary | canarytoken).
            limit: Max devices to return.

        Returns:
            Envelope with the device records (kind, location, live flag,
            last-triggered).
        """
        if self.mock_mode:
            return self._mock_list_devices(kind, limit)
        return await self._real_list_devices(kind, limit)

    async def canary_incident_summary(self, src_host: str) -> dict[str, Any]:
        """Per-attacker-IP rollup across the deception grid.

        Args:
            src_host: The source IP to summarise.

        Returns:
            Envelope with the incident count, incident types, and the distinct
            canaries/tokens the IP tripped, or a ``not_found`` status.
        """
        if self.mock_mode:
            return self._mock_incident_summary(src_host)
        return await self._real_incident_summary(src_host)

    # ----- mock implementations -----

    def _mock_list_incidents(
        self,
        acknowledged: bool | None,
        incident_type_contains: str | None,
        limit: int,
    ) -> dict[str, Any]:
        incidents = [
            i
            for i in CANARY_FIXTURE_INCIDENTS
            if (acknowledged is None or bool(i.get("acknowledged")) is acknowledged)
            and (
                incident_type_contains is None
                or incident_type_contains.lower() in str(i.get("incident_type", "")).lower()
            )
        ][:limit]
        return {
            "status": "success",
            "is_mock": True,
            "acknowledged": acknowledged,
            "incident_type_contains": incident_type_contains,
            "total": len(incidents),
            "incidents": incidents,
        }

    def _mock_list_devices(self, kind: str | None, limit: int) -> dict[str, Any]:
        devices = [
            d for d in CANARY_FIXTURE_DEVICES.values() if kind is None or d.get("kind") == kind
        ][:limit]
        return {
            "status": "success",
            "is_mock": True,
            "kind": kind,
            "total": len(devices),
            "devices": devices,
        }

    def _mock_incident_summary(self, src_host: str) -> dict[str, Any]:
        incidents = [i for i in CANARY_FIXTURE_INCIDENTS if i.get("src_host") == src_host]
        if not incidents:
            return {
                "status": "not_found",
                "is_mock": True,
                "src_host": src_host,
                "message": f"No Canary incidents from '{src_host}'",
            }
        by_type: Counter[str] = Counter(str(i.get("incident_type")) for i in incidents)
        targets = sorted({str(i.get("target")) for i in incidents})
        unacked = sum(1 for i in incidents if not i.get("acknowledged"))
        return {
            "status": "success",
            "is_mock": True,
            "src_host": src_host,
            "incident_count": len(incidents),
            "unacknowledged_count": unacked,
            "incident_types": dict(by_type),
            "decoys_tripped": targets,
            # More than one decoy tripped by one IP = movement through the grid.
            "multi_decoy": len(targets) > 1,
        }

    # ----- real implementations (placeholders, fail-safe) -----

    async def _real_list_incidents(
        self,
        acknowledged: bool | None,
        incident_type_contains: str | None,
        limit: int,
    ) -> dict[str, Any]:
        token = self._get_api_token()
        if not token or token.startswith("<unresolved:"):
            logger.warning(
                "canary: live-mode incident list refused — no API token (%s)",
                _redact_secret(token),
            )
            raise NotImplementedError(
                "Canary live mode requires a resolvable API token (wire "
                "${secret:vault:canary/api_token} or set BTAGENT_CANARY_API_TOKEN)."
            )
        raise NotImplementedError("Canary live list_incidents not yet implemented")

    async def _real_list_devices(self, kind: str | None, limit: int) -> dict[str, Any]:
        token = self._get_api_token()
        if not token or token.startswith("<unresolved:"):
            logger.warning(
                "canary: live-mode device list refused — no API token (%s)",
                _redact_secret(token),
            )
            raise NotImplementedError("Canary live mode requires a resolvable API token")
        raise NotImplementedError("Canary live list_devices not yet implemented")

    async def _real_incident_summary(self, src_host: str) -> dict[str, Any]:
        token = self._get_api_token()
        if not token or token.startswith("<unresolved:"):
            raise NotImplementedError("Canary live mode requires a resolvable API token")
        raise NotImplementedError("Canary live incident_summary not yet implemented")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "canary_list_incidents",
                "description": (
                    "List triggered Thinkst Canary incidents (canarytoken use, "
                    "port scans, SMB/SSH/HTTP interactions) with an acknowledged "
                    "filter and an incident-type substring. Every incident is a "
                    "high-fidelity intruder signal (near-zero false positive)."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "acknowledged": {
                            "type": "boolean",
                            "description": "Optional filter on the acknowledged flag",
                        },
                        "incident_type_contains": {
                            "type": "string",
                            "description": "Optional substring over the incident type",
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
                "name": "canary_list_devices",
                "description": (
                    "List the deployed Canary + Canarytoken inventory (kind, "
                    "location, live flag, last-triggered)."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "kind": {
                            "type": "string",
                            "enum": ["canary", "canarytoken"],
                            "description": "Optional exact device kind",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max devices to return",
                            "default": 50,
                        },
                    },
                },
            },
            {
                "name": "canary_incident_summary",
                "description": (
                    "Per-attacker-IP Canary rollup: incident count, incident "
                    "types, and the distinct decoys tripped — the one-intruder-"
                    "many-decoys movement signal across the deception grid."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "src_host": {"type": "string", "description": "The source IP to summarise"},
                    },
                    "required": ["src_host"],
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances (parity with sibling connectors)
# ---------------------------------------------------------------------------
_server = CanaryMCPServer()


@tool
async def canary_list_incidents(
    acknowledged: bool | None = None,
    incident_type_contains: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """List triggered Thinkst Canary incidents.

    Args:
        acknowledged: Optional filter on the acknowledged flag.
        incident_type_contains: Optional substring over the incident type.
        limit: Max incidents to return.
    """
    return await _server.canary_list_incidents(acknowledged, incident_type_contains, limit)


@tool
async def canary_list_devices(kind: str | None = None, limit: int = 50) -> dict[str, Any]:
    """List the deployed Canary + Canarytoken inventory.

    Args:
        kind: Optional exact filter (canary | canarytoken).
        limit: Max devices to return.
    """
    return await _server.canary_list_devices(kind, limit)


@tool
async def canary_incident_summary(src_host: str) -> dict[str, Any]:
    """Per-attacker-IP Canary rollup across the deception grid.

    Args:
        src_host: The source IP to summarise.
    """
    return await _server.canary_incident_summary(src_host)
