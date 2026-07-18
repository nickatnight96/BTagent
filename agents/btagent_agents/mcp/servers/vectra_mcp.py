"""Vectra AI NDR MCP server connector — Tier-2 slice (#100).

First network-detection-and-response (NDR) connector — a domain distinct from
the Zeek/Corelight connector (which surfaces *raw* conn/dns/ssl logs). Vectra
applies AI models to network traffic and emits scored **detections** and
per-entity **threat/certainty** risk, so its surface is behavioural network
detections rather than raw telemetry. Built in the modern read-only style
(fixtures module, lazy ``${secret:…}`` resolution, guarded live mode, full
contract tests) and mirroring :mod:`btagent_agents.mcp.servers.wiz_mcp` — no
mutation / containment capability, therefore no HITL-gated tool.

Capabilities:

- ``vectra_list_detections(min_threat=0, category=None, state=None,
  limit=50)`` — scored detections with a threat floor, category filter
  (command-and-control / lateral-movement / exfiltration / reconnaissance),
  and state filter (active | fixed).
- ``vectra_list_hosts(min_threat=0, key_assets_only=False, limit=50)`` — the
  host risk inventory (aggregate threat/certainty, key-asset flag).
- ``vectra_host_summary(host)`` — per-host detection rollup: detections by
  category, max threat/certainty, the kill-chain categories seen, and the
  Vectra quadrant (critical / high / medium / low) — the "is this host
  compromised" triage signal (mirrors ``aws_cloudtrail_principal_summary``).

Secret hygiene mirrors the sibling connectors: the Vectra API token is
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

from btagent_agents.mcp.servers._vectra_fixtures import (
    VECTRA_FIXTURE_DETECTIONS,
    VECTRA_FIXTURE_HOSTS,
)

logger = logging.getLogger("btagent.mcp.servers.vectra")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"

# Vectra's threat/certainty quadrant thresholds (the Detect UI's 50/50 split).
_QUADRANT_FLOOR = 50


def _quadrant(threat: int, certainty: int) -> str:
    """Map a (threat, certainty) pair to the Vectra risk quadrant."""
    hi_t = threat >= _QUADRANT_FLOOR
    hi_c = certainty >= _QUADRANT_FLOOR
    if hi_t and hi_c:
        return "critical"
    if hi_t and not hi_c:
        return "high"
    if not hi_t and hi_c:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Secret-redaction helper for log lines local to this module
# ---------------------------------------------------------------------------
def _redact_secret(secret: str) -> str:
    """Return a safe-to-log fingerprint of the Vectra API token.

    Never returns the raw secret; a short suffix fingerprint is emitted only
    when the secret is long enough for the suffix to be non-identifying.
    """
    if not secret or len(secret) < 12:
        return "[redacted]"
    return f"[redacted:vectra-api-token:…{secret[-4:]}]"


# ---------------------------------------------------------------------------
# Vectra NDR MCP server class
# ---------------------------------------------------------------------------
class VectraMCPServer:
    """Vectra AI NDR MCP connector with mock and real modes.

    Default mode is mock (``BTAGENT_MOCK_CONNECTORS=true``) — the connector
    never calls the Vectra API unless explicitly opted out AND an API token
    resolves. The mock path is what CI exercises; live mode is a guarded
    placeholder.
    """

    server_id: str = "vectra"

    DEFAULT_API_TOKEN_REF: str = "${secret:vault:vectra/api_token}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        api_base_url: str | None = None,
        api_token_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self.api_base_url: str = (
            api_base_url or os.getenv("BTAGENT_VECTRA_API_URL") or "https://acme.vectra.ai"
        )
        self._api_token_ref: str = api_token_ref or self.DEFAULT_API_TOKEN_REF

    # ----- safety: never put the token in repr/str -----

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"VectraMCPServer(server_id={self.server_id!r}, "
            f"api_base_url={self.api_base_url!r}, mock_mode={self.mock_mode!r})"
        )

    # ----- lazy secret resolution -----

    def _get_api_token(self) -> str:
        """Resolve the Vectra API token lazily from the configured ref."""
        resolved: str = resolve_secret(self._api_token_ref)
        return resolved

    # ----- tools -----

    async def vectra_list_detections(
        self,
        min_threat: int = 0,
        category: str | None = None,
        state: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List Vectra scored detections.

        Args:
            min_threat: Threat-score floor (0-100).
            category: Optional exact category
                (command-and-control | lateral-movement | exfiltration |
                reconnaissance).
            state: Optional exact state filter (active | fixed).
            limit: Max detections to return.

        Returns:
            Envelope with the matched detection objects.
        """
        if self.mock_mode:
            return self._mock_list_detections(min_threat, category, state, limit)
        return await self._real_list_detections(min_threat, category, state, limit)

    async def vectra_list_hosts(
        self,
        min_threat: int = 0,
        key_assets_only: bool = False,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List the Vectra host risk inventory.

        Args:
            min_threat: Aggregate threat-score floor (0-100).
            key_assets_only: Only return hosts flagged as key assets.
            limit: Max hosts to return.

        Returns:
            Envelope with host risk records (threat/certainty, key-asset flag).
        """
        if self.mock_mode:
            return self._mock_list_hosts(min_threat, key_assets_only, limit)
        return await self._real_list_hosts(min_threat, key_assets_only, limit)

    async def vectra_host_summary(self, host: str) -> dict[str, Any]:
        """Per-host detection rollup.

        Args:
            host: The host name to summarise.

        Returns:
            Envelope with detections-by-category, max threat/certainty, the
            kill-chain categories seen, and the Vectra risk quadrant, or a
            ``not_found`` status.
        """
        if self.mock_mode:
            return self._mock_host_summary(host)
        return await self._real_host_summary(host)

    # ----- mock implementations -----

    def _mock_list_detections(
        self,
        min_threat: int,
        category: str | None,
        state: str | None,
        limit: int,
    ) -> dict[str, Any]:
        detections = [
            d
            for d in VECTRA_FIXTURE_DETECTIONS
            if int(d.get("threat") or 0) >= min_threat
            and (category is None or d.get("category") == category)
            and (state is None or d.get("state") == state)
        ][:limit]
        return {
            "status": "success",
            "is_mock": True,
            "min_threat": min_threat,
            "category": category,
            "detection_state": state,
            "total": len(detections),
            "detections": detections,
        }

    def _mock_list_hosts(
        self,
        min_threat: int,
        key_assets_only: bool,
        limit: int,
    ) -> dict[str, Any]:
        hosts = [
            h
            for h in VECTRA_FIXTURE_HOSTS.values()
            if int(h.get("threat") or 0) >= min_threat
            and (not key_assets_only or bool(h.get("is_key_asset")))
        ][:limit]
        return {
            "status": "success",
            "is_mock": True,
            "min_threat": min_threat,
            "key_assets_only": key_assets_only,
            "total": len(hosts),
            "hosts": hosts,
        }

    def _mock_host_summary(self, host: str) -> dict[str, Any]:
        record = VECTRA_FIXTURE_HOSTS.get(host)
        if record is None:
            return {
                "status": "not_found",
                "is_mock": True,
                "host": host,
                "message": f"Host '{host}' not found in Vectra",
            }
        detections = [
            d for d in VECTRA_FIXTURE_DETECTIONS if (d.get("src_host") or {}).get("name") == host
        ]
        by_category: Counter[str] = Counter(str(d.get("category")) for d in detections)
        max_threat = max((int(d.get("threat") or 0) for d in detections), default=0)
        max_certainty = max((int(d.get("certainty") or 0) for d in detections), default=0)
        return {
            "status": "success",
            "is_mock": True,
            "host": host,
            "ip": record.get("ip"),
            "is_key_asset": bool(record.get("is_key_asset")),
            "detection_count": len(detections),
            "detections_by_category": dict(by_category),
            "kill_chain_categories": sorted(by_category),
            "max_threat": max_threat,
            "max_certainty": max_certainty,
            "quadrant": _quadrant(max_threat, max_certainty),
        }

    # ----- real implementations (placeholders, fail-safe) -----

    async def _real_list_detections(
        self,
        min_threat: int,
        category: str | None,
        state: str | None,
        limit: int,
    ) -> dict[str, Any]:
        token = self._get_api_token()
        if not token or token.startswith("<unresolved:"):
            logger.warning(
                "vectra: live-mode detection list refused — no API token (%s)",
                _redact_secret(token),
            )
            raise NotImplementedError(
                "Vectra live mode requires a resolvable API token (wire "
                "${secret:vault:vectra/api_token} or set BTAGENT_VECTRA_API_TOKEN)."
            )
        raise NotImplementedError("Vectra live list_detections not yet implemented")

    async def _real_list_hosts(
        self,
        min_threat: int,
        key_assets_only: bool,
        limit: int,
    ) -> dict[str, Any]:
        token = self._get_api_token()
        if not token or token.startswith("<unresolved:"):
            logger.warning(
                "vectra: live-mode host list refused — no API token (%s)",
                _redact_secret(token),
            )
            raise NotImplementedError("Vectra live mode requires a resolvable API token")
        raise NotImplementedError("Vectra live list_hosts not yet implemented")

    async def _real_host_summary(self, host: str) -> dict[str, Any]:
        token = self._get_api_token()
        if not token or token.startswith("<unresolved:"):
            raise NotImplementedError("Vectra live mode requires a resolvable API token")
        raise NotImplementedError("Vectra live host_summary not yet implemented")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "vectra_list_detections",
                "description": (
                    "List Vectra AI scored network detections with a threat "
                    "floor, category filter (command-and-control / lateral-"
                    "movement / exfiltration / reconnaissance), and state "
                    "filter. Detections carry threat + certainty scores and "
                    "the source host."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "min_threat": {
                            "type": "integer",
                            "description": "Threat-score floor (0-100)",
                            "default": 0,
                        },
                        "category": {
                            "type": "string",
                            "enum": [
                                "command-and-control",
                                "lateral-movement",
                                "exfiltration",
                                "reconnaissance",
                            ],
                            "description": "Optional exact detection category",
                        },
                        "state": {
                            "type": "string",
                            "enum": ["active", "fixed"],
                            "description": "Optional exact detection state",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max detections to return",
                            "default": 50,
                        },
                    },
                },
            },
            {
                "name": "vectra_list_hosts",
                "description": (
                    "List the Vectra host risk inventory with an aggregate "
                    "threat floor and a key-assets-only filter. Records carry "
                    "threat/certainty scores and the key-asset flag."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "min_threat": {
                            "type": "integer",
                            "description": "Aggregate threat-score floor (0-100)",
                            "default": 0,
                        },
                        "key_assets_only": {
                            "type": "boolean",
                            "description": "Only return key-asset hosts",
                            "default": False,
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max hosts to return",
                            "default": 50,
                        },
                    },
                },
            },
            {
                "name": "vectra_host_summary",
                "description": (
                    "Per-host Vectra detection rollup: detections by category, "
                    "max threat/certainty, the kill-chain categories seen, and "
                    "the risk quadrant (critical/high/medium/low) — the "
                    "is-this-host-compromised triage signal."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "The host name to summarise"},
                    },
                    "required": ["host"],
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances (parity with sibling connectors)
# ---------------------------------------------------------------------------
_server = VectraMCPServer()


@tool
async def vectra_list_detections(
    min_threat: int = 0,
    category: str | None = None,
    state: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """List Vectra AI scored network detections.

    Args:
        min_threat: Threat-score floor (0-100).
        category: Optional exact category (command-and-control | lateral-movement
            | exfiltration | reconnaissance).
        state: Optional exact state filter (active | fixed).
        limit: Max detections to return.
    """
    return await _server.vectra_list_detections(min_threat, category, state, limit)


@tool
async def vectra_list_hosts(
    min_threat: int = 0,
    key_assets_only: bool = False,
    limit: int = 50,
) -> dict[str, Any]:
    """List the Vectra host risk inventory.

    Args:
        min_threat: Aggregate threat-score floor (0-100).
        key_assets_only: Only return hosts flagged as key assets.
        limit: Max hosts to return.
    """
    return await _server.vectra_list_hosts(min_threat, key_assets_only, limit)


@tool
async def vectra_host_summary(host: str) -> dict[str, Any]:
    """Per-host Vectra detection rollup.

    Args:
        host: The host name to summarise.
    """
    return await _server.vectra_host_summary(host)
