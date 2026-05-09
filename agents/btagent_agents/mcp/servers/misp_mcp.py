"""MISP MCP server connector.

Tools:
- misp_search_attributes(value, type)
- misp_get_event(event_id)
- misp_search_iocs(ioc_value)

Mock mode returns realistic sample data (MISP events, attributes,
galaxy clusters, threat levels). Real mode is a placeholder for the
MISP REST API.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from langchain_core.tools import tool

logger = logging.getLogger("btagent.mcp.servers.misp")

MOCK_MODE = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------

_MOCK_EVENTS: dict[str, dict[str, Any]] = {
    "EVT-10042": {
        "event_id": "EVT-10042",
        "info": "CobaltStrike C2 Infrastructure - Operation ShadowStrike",
        "date": "2026-03-20",
        "threat_level_id": "1",
        "threat_level": "High",
        "analysis": "2",
        "analysis_label": "Completed",
        "distribution": "3",
        "distribution_label": "All communities",
        "org": "ACME-CERT",
        "orgc": "ACME-CERT",
        "published": True,
        "timestamp": "2026-03-24T14:00:00Z",
        "tags": [
            {"name": "tlp:amber", "colour": "#FFC000"},
            {"name": 'misp-galaxy:threat-actor="APT-Phantom"'},
            {"name": 'misp-galaxy:mitre-attack-pattern="T1059.001"'},
            {"name": "type:OSINT"},
            {"name": "cobalt-strike"},
        ],
        "galaxies": [
            {
                "name": "Threat Actor",
                "type": "threat-actor",
                "clusters": [
                    {
                        "value": "APT-Phantom",
                        "description": (
                            "State-sponsored threat group targeting "
                            "financial and government sectors."
                        ),
                        "meta": {
                            "country": "Unknown",
                            "motivation": "espionage",
                            "first_seen": "2024-06-01",
                        },
                    },
                ],
            },
            {
                "name": "MITRE ATT&CK",
                "type": "mitre-attack-pattern",
                "clusters": [
                    {
                        "value": "T1059.001 - PowerShell",
                        "description": (
                            "Adversaries may abuse PowerShell commands and scripts for execution."
                        ),
                    },
                    {
                        "value": "T1071.001 - Web Protocols",
                        "description": (
                            "Adversaries may communicate using application layer protocols."
                        ),
                    },
                ],
            },
        ],
        "attributes": [
            {
                "id": "attr-100421",
                "type": "ip-dst",
                "category": "Network activity",
                "value": "185.220.101.42",
                "to_ids": True,
                "comment": "CobaltStrike C2 server",
                "timestamp": "2026-03-20T10:00:00Z",
            },
            {
                "id": "attr-100422",
                "type": "ip-dst",
                "category": "Network activity",
                "value": "45.155.205.233",
                "to_ids": True,
                "comment": "Secondary C2 / payload staging",
                "timestamp": "2026-03-20T10:00:00Z",
            },
            {
                "id": "attr-100423",
                "type": "domain",
                "category": "Network activity",
                "value": "c2-server.xyz",
                "to_ids": True,
                "comment": "Primary C2 domain",
                "timestamp": "2026-03-20T10:00:00Z",
            },
            {
                "id": "attr-100424",
                "type": "domain",
                "category": "Network activity",
                "value": "suspicious-domain.ru",
                "to_ids": True,
                "comment": "Payload distribution domain",
                "timestamp": "2026-03-20T10:00:00Z",
            },
            {
                "id": "attr-100425",
                "type": "sha256",
                "category": "Payload delivery",
                "value": ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                "to_ids": True,
                "comment": "CobaltStrike beacon payload",
                "timestamp": "2026-03-20T10:00:00Z",
            },
            {
                "id": "attr-100426",
                "type": "email-src",
                "category": "Payload delivery",
                "value": "hr-update@acme-notifications.com",
                "to_ids": True,
                "comment": "Phishing sender address",
                "timestamp": "2026-03-20T10:00:00Z",
            },
        ],
        "attribute_count": 6,
    },
    "EVT-10038": {
        "event_id": "EVT-10038",
        "info": "Brute Force Campaign Targeting VPN Infrastructure",
        "date": "2026-03-18",
        "threat_level_id": "2",
        "threat_level": "Medium",
        "analysis": "2",
        "analysis_label": "Completed",
        "distribution": "2",
        "distribution_label": "Connected communities",
        "org": "ACME-CERT",
        "orgc": "ISC-SANS",
        "published": True,
        "timestamp": "2026-03-22T09:00:00Z",
        "tags": [
            {"name": "tlp:green", "colour": "#33FF00"},
            {"name": "type:OSINT"},
            {"name": "brute-force"},
            {"name": 'misp-galaxy:mitre-attack-pattern="T1110.001"'},
        ],
        "galaxies": [
            {
                "name": "MITRE ATT&CK",
                "type": "mitre-attack-pattern",
                "clusters": [
                    {
                        "value": "T1110.001 - Password Guessing",
                        "description": (
                            "Adversaries with no prior knowledge "
                            "of legitimate credentials may guess "
                            "passwords to attempt access."
                        ),
                    },
                ],
            },
        ],
        "attributes": [
            {
                "id": "attr-100381",
                "type": "ip-src",
                "category": "Network activity",
                "value": "185.220.101.42",
                "to_ids": True,
                "comment": "Brute force source IP (Tor exit)",
                "timestamp": "2026-03-18T08:00:00Z",
            },
            {
                "id": "attr-100382",
                "type": "ip-src",
                "category": "Network activity",
                "value": "185.220.101.55",
                "to_ids": True,
                "comment": "Brute force source IP (Tor exit)",
                "timestamp": "2026-03-18T08:00:00Z",
            },
        ],
        "attribute_count": 2,
    },
}


# ---------------------------------------------------------------------------
# MISP MCP server class
# ---------------------------------------------------------------------------
class MISPMCPServer:
    """MISP MCP connector with mock and real modes.

    In mock mode (default via ``BTAGENT_MOCK_CONNECTORS=true``), every
    tool returns realistic sample data suitable for demos and UAT.
    """

    server_id: str = "misp"

    def __init__(self, *, mock_mode: bool | None = None) -> None:
        self.mock_mode = mock_mode if mock_mode is not None else MOCK_MODE

    # ---- tools ----

    async def misp_search_attributes(
        self,
        value: str,
        type: str = "",
    ) -> dict[str, Any]:
        """Search MISP attributes by value and optional type.

        Args:
            value: Attribute value to search for (IP, hash, domain, etc.).
            type: Optional MISP attribute type filter
                  (ip-src, ip-dst, domain, sha256, etc.).

        Returns:
            Matching events with tags and galaxy clusters.
        """
        if self.mock_mode:
            return self._mock_search_attributes(value, type)
        return self._real_search_attributes(value, type)

    async def misp_get_event(
        self,
        event_id: str,
    ) -> dict[str, Any]:
        """Get a full MISP event by ID.

        Args:
            event_id: MISP event ID.

        Returns:
            Full event with attributes, tags, and galaxies.
        """
        if self.mock_mode:
            return self._mock_get_event(event_id)
        return self._real_get_event(event_id)

    async def misp_search_iocs(
        self,
        ioc_value: str,
    ) -> dict[str, Any]:
        """Search for an IOC across all MISP events.

        Args:
            ioc_value: IOC value to search (IP, hash, domain, URL).

        Returns:
            Matching attributes with threat level and event context.
        """
        if self.mock_mode:
            return self._mock_search_iocs(ioc_value)
        return self._real_search_iocs(ioc_value)

    # ---- mock implementations ----

    def _mock_search_attributes(self, value: str, type: str) -> dict[str, Any]:
        matches = []
        for evt in _MOCK_EVENTS.values():
            for attr in evt["attributes"]:
                if value in attr["value"]:
                    if type and attr["type"] != type:
                        continue
                    matches.append(
                        {
                            "attribute": attr,
                            "event_id": evt["event_id"],
                            "event_info": evt["info"],
                            "threat_level": evt["threat_level"],
                            "tags": [t["name"] for t in evt["tags"]],
                        }
                    )
        return {
            "status": "success",
            "value_queried": value,
            "type_filter": type or "any",
            "result_count": len(matches),
            "results": matches,
            "is_mock": True,
        }

    def _mock_get_event(self, event_id: str) -> dict[str, Any]:
        event = _MOCK_EVENTS.get(event_id)
        if event is None:
            return {
                "status": "not_found",
                "event_id": event_id,
                "message": f"Event {event_id} not found",
                "is_mock": True,
            }
        return {
            "status": "success",
            "event": event,
            "is_mock": True,
        }

    def _mock_search_iocs(self, ioc_value: str) -> dict[str, Any]:
        matches = []
        for evt in _MOCK_EVENTS.values():
            for attr in evt["attributes"]:
                if ioc_value == attr["value"]:
                    matches.append(
                        {
                            "attribute_id": attr["id"],
                            "attribute_type": attr["type"],
                            "attribute_value": attr["value"],
                            "category": attr["category"],
                            "comment": attr["comment"],
                            "to_ids": attr["to_ids"],
                            "event_id": evt["event_id"],
                            "event_info": evt["info"],
                            "threat_level": evt["threat_level"],
                            "event_tags": [t["name"] for t in evt["tags"]],
                            "galaxies": [g["name"] for g in evt.get("galaxies", [])],
                        }
                    )
        return {
            "status": "success",
            "ioc_queried": ioc_value,
            "result_count": len(matches),
            "results": matches,
            "is_mock": True,
        }

    # ---- real implementations (placeholders) ----

    def _real_search_attributes(self, value: str, type: str) -> dict[str, Any]:
        raise NotImplementedError("Real MISP attribute search not yet implemented")

    def _real_get_event(self, event_id: str) -> dict[str, Any]:
        raise NotImplementedError("Real MISP get event not yet implemented")

    def _real_search_iocs(self, ioc_value: str) -> dict[str, Any]:
        raise NotImplementedError("Real MISP IOC search not yet implemented")

    # ---- LangChain tool registration helpers ----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        """Return tool metadata for discovery."""
        return [
            {
                "name": "misp_search_attributes",
                "description": (
                    "Search MISP attributes by value and optional "
                    "type. Returns matching events with tags and "
                    "galaxy clusters."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "value": {
                            "type": "string",
                            "description": ("Attribute value to search for"),
                        },
                        "type": {
                            "type": "string",
                            "description": (
                                "MISP attribute type filter (ip-src, ip-dst, domain, sha256)"
                            ),
                            "default": "",
                        },
                    },
                    "required": ["value"],
                },
            },
            {
                "name": "misp_get_event",
                "description": (
                    "Get a full MISP event by ID including all "
                    "attributes, tags, and galaxy clusters."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "event_id": {
                            "type": "string",
                            "description": "MISP event ID",
                        },
                    },
                    "required": ["event_id"],
                },
            },
            {
                "name": "misp_search_iocs",
                "description": (
                    "Search for an IOC value across all MISP "
                    "events. Returns matching attributes with "
                    "threat level and event context."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ioc_value": {
                            "type": "string",
                            "description": ("IOC to search (IP, hash, domain)"),
                        },
                    },
                    "required": ["ioc_value"],
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances
# ---------------------------------------------------------------------------
_server = MISPMCPServer()


@tool
async def misp_search_attributes(
    value: str,
    type: str = "",
) -> dict[str, Any]:
    """Search MISP attributes by value and optional type.

    Args:
        value: Attribute value to search for (IP, hash, domain, etc.).
        type: Optional MISP attribute type filter.
    """
    return await _server.misp_search_attributes(value, type)


@tool
async def misp_get_event(event_id: str) -> dict[str, Any]:
    """Get a full MISP event by ID.

    Args:
        event_id: MISP event ID.
    """
    return await _server.misp_get_event(event_id)


@tool
async def misp_search_iocs(ioc_value: str) -> dict[str, Any]:
    """Search for an IOC across all MISP events.

    Args:
        ioc_value: IOC value to search (IP, hash, domain, URL).
    """
    return await _server.misp_search_iocs(ioc_value)
