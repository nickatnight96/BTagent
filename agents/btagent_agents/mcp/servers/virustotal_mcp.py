"""VirusTotal MCP server connector.

Tools:
- vt_lookup_hash(hash)
- vt_lookup_ip(ip)
- vt_lookup_domain(domain)
- vt_lookup_url(url)

Mock mode returns realistic sample data (detection ratios, engines,
malware families). Real mode is a placeholder for the VirusTotal v3 API.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from langchain_core.tools import tool

logger = logging.getLogger("btagent.mcp.servers.virustotal")

MOCK_MODE = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------

_MOCK_HASH_RESULTS: dict[str, dict[str, Any]] = {
    "default": {
        "sha256": ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "file_type": "PE32 executable (GUI) Intel 80386",
        "file_size": 245760,
        "first_seen": "2026-02-15T12:30:00Z",
        "last_seen": "2026-03-26T06:00:00Z",
        "last_analysis_stats": {
            "malicious": 48,
            "suspicious": 3,
            "undetected": 21,
            "harmless": 0,
            "timeout": 2,
        },
        "detection_ratio": "48/74",
        "popular_threat_classification": {
            "suggested_threat_label": "trojan.cobaltstrike/agent",
            "popular_threat_category": [
                {"value": "trojan", "count": 38},
                {"value": "backdoor", "count": 7},
            ],
            "popular_threat_name": [
                {"value": "cobaltstrike", "count": 22},
                {"value": "beacon", "count": 14},
            ],
        },
        "malware_families": ["CobaltStrike", "Beacon"],
        "tags": [
            "peexe",
            "overlay",
            "signed",
            "revoked-cert",
        ],
        "signature_info": {
            "signer": "Suspicious Software Ltd.",
            "status": "revoked",
            "serial_number": "0A:1B:2C:3D:4E:5F:6A:7B",
        },
        "sandbox_verdicts": {
            "Microsoft Sysinternals": {"category": "malicious"},
            "VirusTotal Jujubox": {"category": "malicious"},
        },
    },
}

_MOCK_IP_RESULTS: dict[str, dict[str, Any]] = {
    "185.220.101.42": {
        "ip": "185.220.101.42",
        "country": "DE",
        "continent": "EU",
        "as_owner": "Tor Exit Node Hosting GmbH",
        "asn": 205100,
        "network": "185.220.101.0/24",
        "last_analysis_stats": {
            "malicious": 14,
            "suspicious": 2,
            "undetected": 62,
            "harmless": 6,
        },
        "reputation": -87,
        "detected_urls": [
            {
                "url": "http://185.220.101.42:8443/pixel.gif",
                "positives": 8,
                "total": 74,
                "scan_date": "2026-03-25T18:00:00Z",
            },
        ],
        "detected_communicating_files": [
            {
                "sha256": ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                "detection_ratio": "48/74",
                "file_type": "PE32 executable",
            },
        ],
        "tags": ["tor-exit-node", "c2-server", "brute-force"],
        "whois": "Registered to: Suspicious Hosting, Frankfurt, DE",
    },
    "45.155.205.233": {
        "ip": "45.155.205.233",
        "country": "RU",
        "continent": "EU",
        "as_owner": "ShadowNet LLC",
        "asn": 394711,
        "network": "45.155.205.0/24",
        "last_analysis_stats": {
            "malicious": 22,
            "suspicious": 5,
            "undetected": 41,
            "harmless": 6,
        },
        "reputation": -94,
        "detected_urls": [
            {
                "url": "https://45.155.205.233/update.bin",
                "positives": 12,
                "total": 74,
                "scan_date": "2026-03-24T10:00:00Z",
            },
        ],
        "detected_communicating_files": [
            {
                "sha256": ("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"),
                "detection_ratio": "52/74",
                "file_type": "PE32+ executable",
            },
        ],
        "tags": ["c2-server", "cobalt-strike", "apt"],
        "whois": "Registered to: Bulletproof Hosting, Moscow, RU",
    },
    "default": {
        "ip": "unknown",
        "country": "US",
        "continent": "NA",
        "as_owner": "Generic ISP Inc.",
        "asn": 12345,
        "network": "0.0.0.0/0",
        "last_analysis_stats": {
            "malicious": 0,
            "suspicious": 0,
            "undetected": 74,
            "harmless": 0,
        },
        "reputation": 0,
        "detected_urls": [],
        "detected_communicating_files": [],
        "tags": [],
        "whois": "No data available",
    },
}

_MOCK_DOMAIN_RESULTS: dict[str, dict[str, Any]] = {
    "suspicious-domain.ru": {
        "domain": "suspicious-domain.ru",
        "registrar": "REG.RU LLC",
        "creation_date": "2026-01-10T00:00:00Z",
        "last_update": "2026-03-20T00:00:00Z",
        "whois": (
            "Registrant: REDACTED FOR PRIVACY\n"
            "Registrar: REG.RU LLC\n"
            "Created: 2026-01-10\n"
            "Nameservers: ns1.shady-dns.ru, ns2.shady-dns.ru"
        ),
        "last_analysis_stats": {
            "malicious": 11,
            "suspicious": 4,
            "undetected": 55,
            "harmless": 4,
        },
        "reputation": -72,
        "categories": {
            "Forcepoint ThreatSeeker": "malicious",
            "BitDefender": "malware",
            "Sophos": "command and control",
        },
        "dns_records": [
            {"type": "A", "value": "45.155.205.233"},
            {"type": "NS", "value": "ns1.shady-dns.ru"},
        ],
        "tags": ["phishing", "c2", "dga"],
    },
    "c2-server.xyz": {
        "domain": "c2-server.xyz",
        "registrar": "Namecheap Inc.",
        "creation_date": "2026-02-01T00:00:00Z",
        "last_update": "2026-03-18T00:00:00Z",
        "whois": (
            "Registrant: WhoisGuard Protected\n"
            "Registrar: Namecheap Inc.\n"
            "Created: 2026-02-01\n"
            "Nameservers: ns1.c2-server.xyz, ns2.c2-server.xyz"
        ),
        "last_analysis_stats": {
            "malicious": 18,
            "suspicious": 6,
            "undetected": 46,
            "harmless": 4,
        },
        "reputation": -91,
        "categories": {
            "Forcepoint ThreatSeeker": "malicious",
            "BitDefender": "malware",
            "Sophos": "command and control",
            "Google Safe Browsing": "malware",
        },
        "dns_records": [
            {"type": "A", "value": "185.220.101.42"},
            {"type": "MX", "value": "mail.c2-server.xyz"},
        ],
        "tags": ["cobalt-strike", "c2", "apt"],
    },
    "default": {
        "domain": "unknown",
        "registrar": "Unknown",
        "creation_date": "N/A",
        "last_update": "N/A",
        "whois": "No data available",
        "last_analysis_stats": {
            "malicious": 0,
            "suspicious": 0,
            "undetected": 74,
            "harmless": 0,
        },
        "reputation": 0,
        "categories": {},
        "dns_records": [],
        "tags": [],
    },
}

_MOCK_URL_RESULTS: dict[str, dict[str, Any]] = {
    "default": {
        "url": "http://suspicious-domain.ru/payload.exe",
        "positives": 31,
        "total": 74,
        "scan_date": "2026-03-26T02:00:00Z",
        "categories": {
            "Forcepoint ThreatSeeker": "malware",
            "BitDefender": "malware",
            "Sophos": "malicious",
        },
        "last_http_response_content_sha256": (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ),
        "final_url": "http://suspicious-domain.ru/payload.exe",
        "tags": ["malware-distribution", "trojan"],
    },
}


# ---------------------------------------------------------------------------
# VirusTotal MCP server class
# ---------------------------------------------------------------------------
class VirusTotalMCPServer:
    """VirusTotal MCP connector with mock and real modes.

    In mock mode (default via ``BTAGENT_MOCK_CONNECTORS=true``), every
    tool returns realistic sample data suitable for demos and UAT.
    """

    server_id: str = "virustotal"

    def __init__(self, *, mock_mode: bool | None = None) -> None:
        self.mock_mode = mock_mode if mock_mode is not None else MOCK_MODE

    # ---- tools ----

    async def vt_lookup_hash(
        self,
        hash: str,
    ) -> dict[str, Any]:
        """Look up a file hash (MD5/SHA1/SHA256) on VirusTotal.

        Args:
            hash: File hash to look up (MD5, SHA1, or SHA256).

        Returns:
            Detection ratio, engines, first/last seen, malware families.
        """
        if self.mock_mode:
            return self._mock_lookup_hash(hash)
        return self._real_lookup_hash(hash)

    async def vt_lookup_ip(
        self,
        ip: str,
    ) -> dict[str, Any]:
        """Look up an IP address on VirusTotal.

        Args:
            ip: IP address to look up.

        Returns:
            Country, AS, detected URLs, communicating files.
        """
        if self.mock_mode:
            return self._mock_lookup_ip(ip)
        return self._real_lookup_ip(ip)

    async def vt_lookup_domain(
        self,
        domain: str,
    ) -> dict[str, Any]:
        """Look up a domain on VirusTotal.

        Args:
            domain: Domain name to look up.

        Returns:
            Registrar, creation date, Whois, last analysis stats.
        """
        if self.mock_mode:
            return self._mock_lookup_domain(domain)
        return self._real_lookup_domain(domain)

    async def vt_lookup_url(
        self,
        url: str,
    ) -> dict[str, Any]:
        """Scan/look up a URL on VirusTotal.

        Args:
            url: URL to scan.

        Returns:
            Positives, total engines, categories.
        """
        if self.mock_mode:
            return self._mock_lookup_url(url)
        return self._real_lookup_url(url)

    # ---- mock implementations ----

    def _mock_lookup_hash(self, hash: str) -> dict[str, Any]:
        result = _MOCK_HASH_RESULTS.get(hash, _MOCK_HASH_RESULTS["default"])
        return {
            "status": "success",
            "hash_queried": hash,
            "data": result,
            "is_mock": True,
        }

    def _mock_lookup_ip(self, ip: str) -> dict[str, Any]:
        result = _MOCK_IP_RESULTS.get(ip, _MOCK_IP_RESULTS["default"])
        if result["ip"] == "unknown":
            result = {**result, "ip": ip}
        return {
            "status": "success",
            "ip_queried": ip,
            "data": result,
            "is_mock": True,
        }

    def _mock_lookup_domain(self, domain: str) -> dict[str, Any]:
        result = _MOCK_DOMAIN_RESULTS.get(domain, _MOCK_DOMAIN_RESULTS["default"])
        if result["domain"] == "unknown":
            result = {**result, "domain": domain}
        return {
            "status": "success",
            "domain_queried": domain,
            "data": result,
            "is_mock": True,
        }

    def _mock_lookup_url(self, url: str) -> dict[str, Any]:
        result = _MOCK_URL_RESULTS.get(url, _MOCK_URL_RESULTS["default"])
        return {
            "status": "success",
            "url_queried": url,
            "data": {**result, "url": url},
            "is_mock": True,
        }

    # ---- real implementations (placeholders) ----

    def _real_lookup_hash(self, hash: str) -> dict[str, Any]:
        raise NotImplementedError("Real VirusTotal hash lookup not yet implemented")

    def _real_lookup_ip(self, ip: str) -> dict[str, Any]:
        raise NotImplementedError("Real VirusTotal IP lookup not yet implemented")

    def _real_lookup_domain(self, domain: str) -> dict[str, Any]:
        raise NotImplementedError("Real VirusTotal domain lookup not yet implemented")

    def _real_lookup_url(self, url: str) -> dict[str, Any]:
        raise NotImplementedError("Real VirusTotal URL lookup not yet implemented")

    # ---- LangChain tool registration helpers ----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        """Return tool metadata for discovery."""
        return [
            {
                "name": "vt_lookup_hash",
                "description": (
                    "Look up a file hash (MD5/SHA1/SHA256) on "
                    "VirusTotal. Returns detection ratio, engines, "
                    "first/last seen, and malware families."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hash": {
                            "type": "string",
                            "description": ("File hash (MD5, SHA1, or SHA256)"),
                        },
                    },
                    "required": ["hash"],
                },
            },
            {
                "name": "vt_lookup_ip",
                "description": (
                    "Look up an IP address on VirusTotal. "
                    "Returns country, AS, detected URLs, and "
                    "communicating files."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip": {
                            "type": "string",
                            "description": "IP address to look up",
                        },
                    },
                    "required": ["ip"],
                },
            },
            {
                "name": "vt_lookup_domain",
                "description": (
                    "Look up a domain on VirusTotal. Returns "
                    "registrar, creation date, Whois, and last "
                    "analysis stats."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Domain name to look up",
                        },
                    },
                    "required": ["domain"],
                },
            },
            {
                "name": "vt_lookup_url",
                "description": (
                    "Scan/look up a URL on VirusTotal. Returns "
                    "positives, total engines, and categories."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "URL to scan",
                        },
                    },
                    "required": ["url"],
                },
            },
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instances
# ---------------------------------------------------------------------------
_server = VirusTotalMCPServer()


@tool
async def vt_lookup_hash(hash: str) -> dict[str, Any]:
    """Look up a file hash (MD5/SHA1/SHA256) on VirusTotal.

    Args:
        hash: File hash to look up (MD5, SHA1, or SHA256).
    """
    return await _server.vt_lookup_hash(hash)


@tool
async def vt_lookup_ip(ip: str) -> dict[str, Any]:
    """Look up an IP address on VirusTotal for reputation data.

    Args:
        ip: IP address to look up.
    """
    return await _server.vt_lookup_ip(ip)


@tool
async def vt_lookup_domain(domain: str) -> dict[str, Any]:
    """Look up a domain on VirusTotal for reputation data.

    Args:
        domain: Domain name to look up.
    """
    return await _server.vt_lookup_domain(domain)


@tool
async def vt_lookup_url(url: str) -> dict[str, Any]:
    """Scan/look up a URL on VirusTotal.

    Args:
        url: URL to scan.
    """
    return await _server.vt_lookup_url(url)
