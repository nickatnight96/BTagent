"""GreyNoise MCP server connector.

Tools:
- gn_ip_lookup(ip)
- gn_quick_check(ip)
- gn_riot_lookup(ip)

Mock mode returns realistic sample data (classifications, noise status,
RIOT data, CVEs, tags). Real mode is a placeholder for the GreyNoise API.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from langchain_core.tools import tool

logger = logging.getLogger("btagent.mcp.servers.greynoise")

MOCK_MODE = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------

_MOCK_IP_CONTEXT: dict[str, dict[str, Any]] = {
    "185.220.101.42": {
        "ip": "185.220.101.42",
        "seen": True,
        "classification": "malicious",
        "noise": True,
        "riot": False,
        "first_seen": "2025-11-10T00:00:00Z",
        "last_seen": "2026-03-26T06:00:00Z",
        "actor": "unknown",
        "tags": [
            "Tor Exit Node",
            "Brute Force SSH",
            "Brute Force RDP",
            "Web Scanner",
            "CobaltStrike C2",
        ],
        "cve": [
            "CVE-2024-6387",
            "CVE-2023-44487",
            "CVE-2024-3400",
        ],
        "metadata": {
            "asn": "AS205100",
            "city": "Frankfurt am Main",
            "country": "Germany",
            "country_code": "DE",
            "organization": "Tor Exit Node Hosting GmbH",
            "os": "Linux",
            "rdns": "exit-node-42.tor-hosting.de",
            "tor": True,
        },
        "raw_data": {
            "scan": [
                {"port": 22, "protocol": "TCP"},
                {"port": 443, "protocol": "TCP"},
                {"port": 8443, "protocol": "TCP"},
                {"port": 3389, "protocol": "TCP"},
            ],
            "web": {
                "paths": [
                    "/login",
                    "/.env",
                    "/wp-admin",
                    "/api/v1/auth",
                ],
                "useragents": [
                    "Mozilla/5.0 (compatible; scanning)",
                    "python-requests/2.31.0",
                ],
            },
            "ja3": [
                {
                    "fingerprint": ("a0e9f5d64349fb13191bc781f81f42e1"),
                    "port": 443,
                },
            ],
        },
        "vpn": False,
        "vpn_service": "",
        "bot": False,
    },
    "45.155.205.233": {
        "ip": "45.155.205.233",
        "seen": True,
        "classification": "malicious",
        "noise": True,
        "riot": False,
        "first_seen": "2026-01-05T00:00:00Z",
        "last_seen": "2026-03-26T04:00:00Z",
        "actor": "unknown",
        "tags": [
            "Malware C2",
            "Web Scanner",
            "Metasploit",
        ],
        "cve": [
            "CVE-2024-6387",
            "CVE-2024-21887",
        ],
        "metadata": {
            "asn": "AS394711",
            "city": "Moscow",
            "country": "Russia",
            "country_code": "RU",
            "organization": "ShadowNet LLC",
            "os": "Linux",
            "rdns": "srv1.shadownet.ru",
            "tor": False,
        },
        "raw_data": {
            "scan": [
                {"port": 22, "protocol": "TCP"},
                {"port": 443, "protocol": "TCP"},
                {"port": 4444, "protocol": "TCP"},
            ],
            "web": {
                "paths": ["/update.bin", "/gate.php"],
                "useragents": ["curl/8.5.0"],
            },
        },
        "vpn": False,
        "vpn_service": "",
        "bot": False,
    },
    "8.8.8.8": {
        "ip": "8.8.8.8",
        "seen": True,
        "classification": "benign",
        "noise": False,
        "riot": True,
        "first_seen": "2020-01-01T00:00:00Z",
        "last_seen": "2026-03-26T08:00:00Z",
        "actor": "Google",
        "tags": [],
        "cve": [],
        "metadata": {
            "asn": "AS15169",
            "city": "Mountain View",
            "country": "United States",
            "country_code": "US",
            "organization": "Google LLC",
            "os": "unknown",
            "rdns": "dns.google",
            "tor": False,
        },
        "vpn": False,
        "vpn_service": "",
        "bot": False,
    },
    "default": {
        "ip": "unknown",
        "seen": False,
        "classification": "unknown",
        "noise": False,
        "riot": False,
        "first_seen": None,
        "last_seen": None,
        "actor": "unknown",
        "tags": [],
        "cve": [],
        "metadata": {
            "asn": "",
            "city": "",
            "country": "",
            "country_code": "",
            "organization": "",
            "os": "",
            "rdns": "",
            "tor": False,
        },
        "vpn": False,
        "vpn_service": "",
        "bot": False,
    },
}

_MOCK_RIOT_DATA: dict[str, dict[str, Any]] = {
    "8.8.8.8": {
        "ip": "8.8.8.8",
        "riot": True,
        "category": "public_dns",
        "name": "Google Public DNS",
        "description": ("Google's public DNS resolver service."),
        "explanation": ("This IP belongs to Google Public DNS, a widely-used legitimate service."),
        "last_updated": "2026-03-25T00:00:00Z",
        "reference": "https://developers.google.com/speed/public-dns",
        "trust_level": "1",
        "trust_label": "Reasonably Ignore",
    },
    "13.107.42.14": {
        "ip": "13.107.42.14",
        "riot": True,
        "category": "cdn",
        "name": "Microsoft 365",
        "description": "Microsoft 365 service endpoint.",
        "explanation": ("This IP belongs to Microsoft 365 infrastructure and is a known service."),
        "last_updated": "2026-03-25T00:00:00Z",
        "reference": "https://learn.microsoft.com/en-us/microsoft-365/",
        "trust_level": "1",
        "trust_label": "Reasonably Ignore",
    },
    "default": {
        "ip": "unknown",
        "riot": False,
        "category": "unknown",
        "name": "Not Found",
        "description": "IP not found in RIOT dataset.",
        "explanation": ("This IP is not part of any known benign service."),
        "last_updated": None,
        "reference": None,
        "trust_level": "0",
        "trust_label": "Unknown",
    },
}


# ---------------------------------------------------------------------------
# GreyNoise MCP server class
# ---------------------------------------------------------------------------
class GreyNoiseMCPServer:
    """GreyNoise MCP connector with mock and real modes.

    In mock mode (default via ``BTAGENT_MOCK_CONNECTORS=true``), every
    tool returns realistic sample data suitable for demos and UAT.
    """

    server_id: str = "greynoise"

    def __init__(self, *, mock_mode: bool | None = None) -> None:
        self.mock_mode = mock_mode if mock_mode is not None else MOCK_MODE

    # ---- tools ----

    async def gn_ip_lookup(
        self,
        ip: str,
    ) -> dict[str, Any]:
        """Full IP context lookup on GreyNoise.

        Args:
            ip: IP address to look up.

        Returns:
            Classification, noise status, RIOT, tags, CVEs, metadata.
        """
        if self.mock_mode:
            return self._mock_ip_lookup(ip)
        return self._real_ip_lookup(ip)

    async def gn_quick_check(
        self,
        ip: str,
    ) -> dict[str, Any]:
        """Quick noise/RIOT check for an IP on GreyNoise.

        Args:
            ip: IP address to check.

        Returns:
            Noise bool, RIOT bool, classification.
        """
        if self.mock_mode:
            return self._mock_quick_check(ip)
        return self._real_quick_check(ip)

    async def gn_riot_lookup(
        self,
        ip: str,
    ) -> dict[str, Any]:
        """RIOT (Rule It Out) lookup for an IP on GreyNoise.

        Args:
            ip: IP address to check against RIOT dataset.

        Returns:
            Whether IP is a known benign service, provider, trust level.
        """
        if self.mock_mode:
            return self._mock_riot_lookup(ip)
        return self._real_riot_lookup(ip)

    # ---- mock implementations ----

    def _mock_ip_lookup(self, ip: str) -> dict[str, Any]:
        result = _MOCK_IP_CONTEXT.get(ip, _MOCK_IP_CONTEXT["default"])
        if result["ip"] == "unknown":
            result = {**result, "ip": ip}
        return {
            "status": "success",
            "ip_queried": ip,
            "data": result,
            "is_mock": True,
        }

    def _mock_quick_check(self, ip: str) -> dict[str, Any]:
        ctx = _MOCK_IP_CONTEXT.get(ip, _MOCK_IP_CONTEXT["default"])
        return {
            "status": "success",
            "ip": ip,
            "noise": ctx["noise"],
            "riot": ctx["riot"],
            "classification": ctx["classification"],
            "is_mock": True,
        }

    def _mock_riot_lookup(self, ip: str) -> dict[str, Any]:
        result = _MOCK_RIOT_DATA.get(ip, _MOCK_RIOT_DATA["default"])
        if result["ip"] == "unknown":
            result = {**result, "ip": ip}
        return {
            "status": "success",
            "ip_queried": ip,
            "data": result,
            "is_mock": True,
        }

    # ---- real implementations (placeholders) ----

    def _real_ip_lookup(self, ip: str) -> dict[str, Any]:
        raise NotImplementedError("Real GreyNoise IP lookup not yet implemented")

    def _real_quick_check(self, ip: str) -> dict[str, Any]:
        raise NotImplementedError("Real GreyNoise quick check not yet implemented")

    def _real_riot_lookup(self, ip: str) -> dict[str, Any]:
        raise NotImplementedError("Real GreyNoise RIOT lookup not yet implemented")

    # ---- LangChain tool registration helpers ----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        """Return tool metadata for discovery."""
        return [
            {
                "name": "gn_ip_lookup",
                "description": (
                    "Full IP context lookup on GreyNoise. "
                    "Returns classification (benign/malicious/"
                    "unknown), noise status, RIOT, tags, and CVEs."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip": {
                            "type": "string",
                            "description": ("IP address to look up"),
                        },
                    },
                    "required": ["ip"],
                },
            },
            {
                "name": "gn_quick_check",
                "description": (
                    "Quick noise and RIOT check for an IP on "
                    "GreyNoise. Returns noise bool, RIOT bool, "
                    "and classification."
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
                "name": "gn_riot_lookup",
                "description": (
                    "RIOT (Rule It Out) lookup on GreyNoise. "
                    "Checks if an IP is a known benign service "
                    "and returns provider and trust level."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip": {
                            "type": "string",
                            "description": ("IP address to check against RIOT dataset"),
                        },
                    },
                    "required": ["ip"],
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances
# ---------------------------------------------------------------------------
_server = GreyNoiseMCPServer()


@tool
async def gn_ip_lookup(ip: str) -> dict[str, Any]:
    """Full IP context lookup on GreyNoise.

    Args:
        ip: IP address to look up.
    """
    return await _server.gn_ip_lookup(ip)


@tool
async def gn_quick_check(ip: str) -> dict[str, Any]:
    """Quick noise and RIOT check for an IP on GreyNoise.

    Args:
        ip: IP address to check.
    """
    return await _server.gn_quick_check(ip)


@tool
async def gn_riot_lookup(ip: str) -> dict[str, Any]:
    """RIOT (Rule It Out) lookup on GreyNoise.

    Args:
        ip: IP address to check against RIOT dataset.
    """
    return await _server.gn_riot_lookup(ip)
