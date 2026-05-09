"""Shodan MCP server connector.

Tools:
- shodan_host_info(ip)
- shodan_search(query)
- shodan_dns_resolve(hostnames)

Mock mode returns realistic sample data (open ports, services, vulns,
geolocation). Real mode is a placeholder for the Shodan REST API.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from langchain_core.tools import tool

logger = logging.getLogger("btagent.mcp.servers.shodan")

MOCK_MODE = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------

_MOCK_HOST_RESULTS: dict[str, dict[str, Any]] = {
    "185.220.101.42": {
        "ip_str": "185.220.101.42",
        "hostnames": ["exit-node-42.tor-hosting.de"],
        "org": "Tor Exit Node Hosting GmbH",
        "isp": "Tor Exit Node Hosting GmbH",
        "asn": "AS205100",
        "os": "Linux 5.15",
        "country_code": "DE",
        "country_name": "Germany",
        "city": "Frankfurt am Main",
        "latitude": 50.1109,
        "longitude": 8.6821,
        "ports": [22, 80, 443, 8443, 9001, 9030],
        "vulns": ["CVE-2024-6387", "CVE-2023-44487"],
        "data": [
            {
                "port": 22,
                "transport": "tcp",
                "product": "OpenSSH",
                "version": "8.9p1",
                "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
            },
            {
                "port": 443,
                "transport": "tcp",
                "product": "nginx",
                "version": "1.18.0",
                "ssl": {
                    "cert": {
                        "subject": {
                            "CN": "c2-server.xyz",
                        },
                        "issuer": {
                            "O": "Let's Encrypt",
                            "CN": "R3",
                        },
                        "expires": "2026-06-15T00:00:00Z",
                    },
                },
            },
            {
                "port": 8443,
                "transport": "tcp",
                "product": "CobaltStrike Beacon",
                "banner": "HTTP/1.1 200 OK\r\nContent-Type: text/html",
                "http": {
                    "title": "404 Not Found",
                    "server": "nginx",
                },
            },
            {
                "port": 9001,
                "transport": "tcp",
                "product": "Tor OR",
                "version": "0.4.8.10",
            },
        ],
        "last_update": "2026-03-25T22:00:00Z",
        "tags": ["tor", "vpn", "c2"],
    },
    "45.155.205.233": {
        "ip_str": "45.155.205.233",
        "hostnames": ["srv1.shadownet.ru"],
        "org": "ShadowNet LLC",
        "isp": "ShadowNet LLC",
        "asn": "AS394711",
        "os": "Linux 6.1",
        "country_code": "RU",
        "country_name": "Russia",
        "city": "Moscow",
        "latitude": 55.7558,
        "longitude": 37.6173,
        "ports": [22, 80, 443, 4444, 8080],
        "vulns": ["CVE-2024-6387"],
        "data": [
            {
                "port": 22,
                "transport": "tcp",
                "product": "OpenSSH",
                "version": "9.2p1",
            },
            {
                "port": 443,
                "transport": "tcp",
                "product": "nginx",
                "version": "1.22.1",
                "ssl": {
                    "cert": {
                        "subject": {
                            "CN": "suspicious-domain.ru",
                        },
                        "issuer": {
                            "O": "Let's Encrypt",
                            "CN": "R3",
                        },
                    },
                },
            },
            {
                "port": 4444,
                "transport": "tcp",
                "product": "Metasploit",
                "banner": "Meterpreter reverse TCP handler",
            },
        ],
        "last_update": "2026-03-26T01:00:00Z",
        "tags": ["malware", "c2", "bulletproof-hosting"],
    },
    "default": {
        "ip_str": "unknown",
        "hostnames": [],
        "org": "Unknown",
        "isp": "Unknown",
        "asn": "AS0",
        "os": None,
        "country_code": "US",
        "country_name": "United States",
        "city": "Unknown",
        "latitude": 0.0,
        "longitude": 0.0,
        "ports": [],
        "vulns": [],
        "data": [],
        "last_update": "2026-03-26T00:00:00Z",
        "tags": [],
    },
}

_MOCK_SEARCH_RESULTS: dict[str, dict[str, Any]] = {
    "default": {
        "total": 2,
        "matches": [
            {
                "ip_str": "185.220.101.42",
                "port": 8443,
                "org": "Tor Exit Node Hosting GmbH",
                "product": "CobaltStrike Beacon",
                "os": "Linux 5.15",
                "location": {
                    "country_code": "DE",
                    "city": "Frankfurt am Main",
                },
                "hostnames": ["exit-node-42.tor-hosting.de"],
                "timestamp": "2026-03-25T22:00:00Z",
            },
            {
                "ip_str": "45.155.205.233",
                "port": 4444,
                "org": "ShadowNet LLC",
                "product": "Metasploit",
                "os": "Linux 6.1",
                "location": {
                    "country_code": "RU",
                    "city": "Moscow",
                },
                "hostnames": ["srv1.shadownet.ru"],
                "timestamp": "2026-03-26T01:00:00Z",
            },
        ],
    },
}

_MOCK_DNS_RESULTS: dict[str, dict[str, str]] = {
    "c2-server.xyz": "185.220.101.42",
    "suspicious-domain.ru": "45.155.205.233",
    "data.evil-c2.example.com": "185.220.101.42",
    "vpn.acme-corp.com": "10.0.1.5",
}


# ---------------------------------------------------------------------------
# Shodan MCP server class
# ---------------------------------------------------------------------------
class ShodanMCPServer:
    """Shodan MCP connector with mock and real modes.

    In mock mode (default via ``BTAGENT_MOCK_CONNECTORS=true``), every
    tool returns realistic sample data suitable for demos and UAT.
    """

    server_id: str = "shodan"

    def __init__(self, *, mock_mode: bool | None = None) -> None:
        self.mock_mode = mock_mode if mock_mode is not None else MOCK_MODE

    # ---- tools ----

    async def shodan_host_info(
        self,
        ip: str,
    ) -> dict[str, Any]:
        """Get detailed host information from Shodan.

        Args:
            ip: IP address to look up.

        Returns:
            Open ports, services, vulns, OS, location, ISP.
        """
        if self.mock_mode:
            return self._mock_host_info(ip)
        return self._real_host_info(ip)

    async def shodan_search(
        self,
        query: str,
    ) -> dict[str, Any]:
        """Search Shodan for hosts matching a query.

        Args:
            query: Shodan search query (e.g. 'product:CobaltStrike').

        Returns:
            Matching hosts with services and metadata.
        """
        if self.mock_mode:
            return self._mock_search(query)
        return self._real_search(query)

    async def shodan_dns_resolve(
        self,
        hostnames: str,
    ) -> dict[str, Any]:
        """Resolve hostnames to IP addresses via Shodan DNS.

        Args:
            hostnames: Comma-separated list of hostnames to resolve.

        Returns:
            Hostname-to-IP mappings.
        """
        if self.mock_mode:
            return self._mock_dns_resolve(hostnames)
        return self._real_dns_resolve(hostnames)

    # ---- mock implementations ----

    def _mock_host_info(self, ip: str) -> dict[str, Any]:
        result = _MOCK_HOST_RESULTS.get(ip, _MOCK_HOST_RESULTS["default"])
        if result["ip_str"] == "unknown":
            result = {**result, "ip_str": ip}
        return {
            "status": "success",
            "ip_queried": ip,
            "data": result,
            "is_mock": True,
        }

    def _mock_search(self, query: str) -> dict[str, Any]:
        result = _MOCK_SEARCH_RESULTS.get(query, _MOCK_SEARCH_RESULTS["default"])
        return {
            "status": "success",
            "query": query,
            "data": result,
            "is_mock": True,
        }

    def _mock_dns_resolve(self, hostnames: str) -> dict[str, Any]:
        names = [h.strip() for h in hostnames.split(",")]
        mappings: dict[str, str | None] = {}
        for name in names:
            mappings[name] = _MOCK_DNS_RESULTS.get(name)
        return {
            "status": "success",
            "hostnames_queried": names,
            "mappings": mappings,
            "is_mock": True,
        }

    # ---- real implementations (placeholders) ----

    def _real_host_info(self, ip: str) -> dict[str, Any]:
        raise NotImplementedError("Real Shodan host info not yet implemented")

    def _real_search(self, query: str) -> dict[str, Any]:
        raise NotImplementedError("Real Shodan search not yet implemented")

    def _real_dns_resolve(self, hostnames: str) -> dict[str, Any]:
        raise NotImplementedError("Real Shodan DNS resolve not yet implemented")

    # ---- LangChain tool registration helpers ----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        """Return tool metadata for discovery."""
        return [
            {
                "name": "shodan_host_info",
                "description": (
                    "Get detailed host information from Shodan "
                    "including open ports, services, vulnerabilities, "
                    "OS, location, and ISP."
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
                "name": "shodan_search",
                "description": (
                    "Search Shodan for hosts matching a query. "
                    "Returns matching hosts with services and "
                    "metadata."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": ("Shodan search query (e.g. 'product:CobaltStrike')"),
                        },
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "shodan_dns_resolve",
                "description": (
                    "Resolve hostnames to IP addresses via "
                    "Shodan DNS. Accepts comma-separated hostnames."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hostnames": {
                            "type": "string",
                            "description": ("Comma-separated hostnames to resolve"),
                        },
                    },
                    "required": ["hostnames"],
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances
# ---------------------------------------------------------------------------
_server = ShodanMCPServer()


@tool
async def shodan_host_info(ip: str) -> dict[str, Any]:
    """Get detailed host information from Shodan.

    Args:
        ip: IP address to look up.
    """
    return await _server.shodan_host_info(ip)


@tool
async def shodan_search(query: str) -> dict[str, Any]:
    """Search Shodan for hosts matching a query.

    Args:
        query: Shodan search query (e.g. 'product:CobaltStrike').
    """
    return await _server.shodan_search(query)


@tool
async def shodan_dns_resolve(hostnames: str) -> dict[str, Any]:
    """Resolve hostnames to IP addresses via Shodan DNS.

    Args:
        hostnames: Comma-separated list of hostnames to resolve.
    """
    return await _server.shodan_dns_resolve(hostnames)
