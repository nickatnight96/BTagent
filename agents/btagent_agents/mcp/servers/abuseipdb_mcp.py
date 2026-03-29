"""AbuseIPDB MCP server connector.

Tools:
- abuseipdb_check(ip)
- abuseipdb_check_block(network)

Mock mode returns realistic sample data (abuse confidence scores,
reports, categories, ISP info). Real mode is a placeholder for the
AbuseIPDB v2 API.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from langchain_core.tools import tool

logger = logging.getLogger("btagent.mcp.servers.abuseipdb")

MOCK_MODE = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------

_MOCK_IP_CHECK: dict[str, dict[str, Any]] = {
    "185.220.101.42": {
        "ipAddress": "185.220.101.42",
        "isPublic": True,
        "ipVersion": 4,
        "isWhitelisted": False,
        "abuseConfidenceScore": 100,
        "countryCode": "DE",
        "countryName": "Germany",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Tor Exit Node Hosting GmbH",
        "domain": "tor-hosting.de",
        "hostnames": ["exit-node-42.tor-hosting.de"],
        "isTor": True,
        "totalReports": 4872,
        "numDistinctUsers": 1243,
        "lastReportedAt": "2026-03-26T07:55:00Z",
        "categories": [
            {"id": 14, "name": "Port Scan", "count": 1520},
            {"id": 18, "name": "Brute-Force", "count": 2104},
            {"id": 15, "name": "Hacking", "count": 890},
            {"id": 21, "name": "Web App Attack", "count": 358},
        ],
        "reports": [
            {
                "reportedAt": "2026-03-26T07:55:00Z",
                "comment": ("SSH brute force attack detected from this Tor exit node"),
                "categories": [18],
                "reporterId": 48291,
                "reporterCountryCode": "US",
            },
            {
                "reportedAt": "2026-03-26T06:30:00Z",
                "comment": ("Attempted credential stuffing on VPN endpoint"),
                "categories": [18, 15],
                "reporterId": 72104,
                "reporterCountryCode": "GB",
            },
            {
                "reportedAt": "2026-03-25T22:10:00Z",
                "comment": ("Port scanning multiple hosts on TCP/22, TCP/3389"),
                "categories": [14],
                "reporterId": 15832,
                "reporterCountryCode": "DE",
            },
        ],
    },
    "45.155.205.233": {
        "ipAddress": "45.155.205.233",
        "isPublic": True,
        "ipVersion": 4,
        "isWhitelisted": False,
        "abuseConfidenceScore": 97,
        "countryCode": "RU",
        "countryName": "Russia",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "ShadowNet LLC",
        "domain": "shadownet.ru",
        "hostnames": ["srv1.shadownet.ru"],
        "isTor": False,
        "totalReports": 2156,
        "numDistinctUsers": 687,
        "lastReportedAt": "2026-03-26T05:00:00Z",
        "categories": [
            {"id": 15, "name": "Hacking", "count": 1022},
            {
                "id": 23,
                "name": "Malware Distribution",
                "count": 678,
            },
            {"id": 18, "name": "Brute-Force", "count": 456},
        ],
        "reports": [
            {
                "reportedAt": "2026-03-26T05:00:00Z",
                "comment": ("Malware C2 traffic observed to this host"),
                "categories": [23, 15],
                "reporterId": 33102,
                "reporterCountryCode": "NL",
            },
            {
                "reportedAt": "2026-03-25T18:30:00Z",
                "comment": ("CobaltStrike beacon callback to this IP"),
                "categories": [15, 23],
                "reporterId": 99201,
                "reporterCountryCode": "US",
            },
        ],
    },
    "default": {
        "ipAddress": "unknown",
        "isPublic": True,
        "ipVersion": 4,
        "isWhitelisted": False,
        "abuseConfidenceScore": 0,
        "countryCode": "US",
        "countryName": "United States",
        "usageType": "ISP",
        "isp": "Generic ISP Inc.",
        "domain": "generic-isp.com",
        "hostnames": [],
        "isTor": False,
        "totalReports": 0,
        "numDistinctUsers": 0,
        "lastReportedAt": None,
        "categories": [],
        "reports": [],
    },
}

_MOCK_BLOCK_CHECK: dict[str, dict[str, Any]] = {
    "185.220.101.0/24": {
        "networkAddress": "185.220.101.0",
        "netmask": "255.255.255.0",
        "minAddress": "185.220.101.1",
        "maxAddress": "185.220.101.254",
        "numPossibleHosts": 254,
        "addressSpaceDesc": "Tor Exit Node Hosting GmbH",
        "reportedAddress": [
            {
                "ipAddress": "185.220.101.42",
                "numReports": 4872,
                "mostRecentReport": "2026-03-26T07:55:00Z",
                "abuseConfidenceScore": 100,
                "countryCode": "DE",
            },
            {
                "ipAddress": "185.220.101.55",
                "numReports": 3219,
                "mostRecentReport": "2026-03-26T06:00:00Z",
                "abuseConfidenceScore": 98,
                "countryCode": "DE",
            },
            {
                "ipAddress": "185.220.101.78",
                "numReports": 2801,
                "mostRecentReport": "2026-03-25T23:00:00Z",
                "abuseConfidenceScore": 95,
                "countryCode": "DE",
            },
        ],
        "networkScore": 98,
    },
    "45.155.205.0/24": {
        "networkAddress": "45.155.205.0",
        "netmask": "255.255.255.0",
        "minAddress": "45.155.205.1",
        "maxAddress": "45.155.205.254",
        "numPossibleHosts": 254,
        "addressSpaceDesc": "ShadowNet LLC",
        "reportedAddress": [
            {
                "ipAddress": "45.155.205.233",
                "numReports": 2156,
                "mostRecentReport": "2026-03-26T05:00:00Z",
                "abuseConfidenceScore": 97,
                "countryCode": "RU",
            },
            {
                "ipAddress": "45.155.205.100",
                "numReports": 1544,
                "mostRecentReport": "2026-03-25T20:00:00Z",
                "abuseConfidenceScore": 89,
                "countryCode": "RU",
            },
        ],
        "networkScore": 93,
    },
    "default": {
        "networkAddress": "0.0.0.0",
        "netmask": "255.255.255.0",
        "minAddress": "0.0.0.1",
        "maxAddress": "0.0.0.254",
        "numPossibleHosts": 254,
        "addressSpaceDesc": "Unknown",
        "reportedAddress": [],
        "networkScore": 0,
    },
}


# ---------------------------------------------------------------------------
# AbuseIPDB MCP server class
# ---------------------------------------------------------------------------
class AbuseIPDBMCPServer:
    """AbuseIPDB MCP connector with mock and real modes.

    In mock mode (default via ``BTAGENT_MOCK_CONNECTORS=true``), every
    tool returns realistic sample data suitable for demos and UAT.
    """

    server_id: str = "abuseipdb"

    def __init__(self, *, mock_mode: bool | None = None) -> None:
        self.mock_mode = mock_mode if mock_mode is not None else MOCK_MODE

    # ---- tools ----

    async def abuseipdb_check(
        self,
        ip: str,
    ) -> dict[str, Any]:
        """Check an IP address against AbuseIPDB.

        Args:
            ip: IP address to check.

        Returns:
            Abuse confidence score, total reports, country, ISP,
            usage type, and categories.
        """
        if self.mock_mode:
            return self._mock_check(ip)
        return self._real_check(ip)

    async def abuseipdb_check_block(
        self,
        network: str,
    ) -> dict[str, Any]:
        """Check a CIDR network block against AbuseIPDB.

        Args:
            network: CIDR notation network block (e.g. 185.220.101.0/24).

        Returns:
            Network abuse score and reported addresses within the block.
        """
        if self.mock_mode:
            return self._mock_check_block(network)
        return self._real_check_block(network)

    # ---- mock implementations ----

    def _mock_check(self, ip: str) -> dict[str, Any]:
        result = _MOCK_IP_CHECK.get(ip, _MOCK_IP_CHECK["default"])
        if result["ipAddress"] == "unknown":
            result = {**result, "ipAddress": ip}
        return {
            "status": "success",
            "ip_queried": ip,
            "data": result,
            "is_mock": True,
        }

    def _mock_check_block(self, network: str) -> dict[str, Any]:
        result = _MOCK_BLOCK_CHECK.get(network, _MOCK_BLOCK_CHECK["default"])
        return {
            "status": "success",
            "network_queried": network,
            "data": result,
            "is_mock": True,
        }

    # ---- real implementations (placeholders) ----

    def _real_check(self, ip: str) -> dict[str, Any]:
        raise NotImplementedError("Real AbuseIPDB check not yet implemented")

    def _real_check_block(self, network: str) -> dict[str, Any]:
        raise NotImplementedError("Real AbuseIPDB check block not yet implemented")

    # ---- LangChain tool registration helpers ----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        """Return tool metadata for discovery."""
        return [
            {
                "name": "abuseipdb_check",
                "description": (
                    "Check an IP address against AbuseIPDB. "
                    "Returns abuse confidence score, total "
                    "reports, country, ISP, usage type, and "
                    "report categories."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip": {
                            "type": "string",
                            "description": ("IP address to check"),
                        },
                    },
                    "required": ["ip"],
                },
            },
            {
                "name": "abuseipdb_check_block",
                "description": (
                    "Check a CIDR network block against "
                    "AbuseIPDB. Returns network abuse score "
                    "and reported addresses within the block."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "network": {
                            "type": "string",
                            "description": ("CIDR notation network (e.g. 185.220.101.0/24)"),
                        },
                    },
                    "required": ["network"],
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances
# ---------------------------------------------------------------------------
_server = AbuseIPDBMCPServer()


@tool
async def abuseipdb_check(ip: str) -> dict[str, Any]:
    """Check an IP address against AbuseIPDB.

    Args:
        ip: IP address to check.
    """
    return await _server.abuseipdb_check(ip)


@tool
async def abuseipdb_check_block(network: str) -> dict[str, Any]:
    """Check a CIDR network block against AbuseIPDB.

    Args:
        network: CIDR notation network block (e.g. 185.220.101.0/24).
    """
    return await _server.abuseipdb_check_block(network)
