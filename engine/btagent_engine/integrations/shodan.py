"""Shodan integration node.

Single host-lookup node following the GreyNoise reference shape (see
``greynoise.py``):

* ``BTAGENT_MOCK_CONNECTORS=true`` returns realistic, deterministic
  mock fixtures with two pinned hosts plus a clean fall-through for
  any other input.
* The production path raises ``NotImplementedError`` -- the real
  Shodan REST client + credential vault wiring ships in a Sprint 2
  follow-up. Failing loudly prevents a misconfigured prod env from
  silently returning mock data.
* No imports from ``btagent_agents`` / ``btagent_backend``.
"""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel, Field

from btagent_engine.integrations._manifests import SHODAN_MANIFEST
from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)


def _mock_mode_enabled() -> bool:
    """Resolve the mock-mode flag at call time so tests can flip it."""
    return os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Mock fixtures
# ---------------------------------------------------------------------------

_MOCK_HOSTS: dict[str, dict[str, Any]] = {
    "185.220.101.42": {
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
        "services": [
            {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "8.9p1"},
            {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.18.0"},
            {"port": 8443, "transport": "tcp", "product": "CobaltStrike Beacon"},
            {"port": 9001, "transport": "tcp", "product": "Tor OR", "version": "0.4.8.10"},
        ],
        "tags": ["tor", "vpn", "c2"],
        "last_update": "2026-03-25T22:00:00Z",
    },
    "45.155.205.233": {
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
        "services": [
            {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "9.2p1"},
            {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.22.1"},
            {"port": 4444, "transport": "tcp", "product": "Metasploit"},
        ],
        "tags": ["malware", "c2", "bulletproof-hosting"],
        "last_update": "2026-03-26T01:00:00Z",
    },
}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ShodanService(BaseModel):
    port: int = Field(..., description="TCP/UDP port number.")
    transport: str = Field(default="tcp", description="Transport protocol (tcp/udp).")
    product: str | None = Field(default=None, description="Detected service / product name.")
    version: str | None = Field(default=None, description="Detected service version, if known.")


class ShodanHostLookupInput(BaseModel):
    ip: str = Field(
        ...,
        description="IPv4 / IPv6 address to look up on Shodan.",
        examples=["185.220.101.42", "8.8.8.8"],
    )


class ShodanHostLookupOutput(BaseModel):
    seen: bool = Field(
        default=False,
        description="True if Shodan has any record of this host.",
    )
    hostnames: list[str] = Field(
        default_factory=list,
        description="DNS names associated with the host.",
    )
    org: str | None = Field(default=None, description="Organisation operating the host.")
    isp: str | None = Field(default=None, description="ISP for the host.")
    asn: str | None = Field(default=None, description="Autonomous System Number, e.g. 'AS205100'.")
    os: str | None = Field(default=None, description="Detected operating system, if known.")
    country_code: str | None = Field(
        default=None,
        description="ISO country code of the host's location.",
    )
    country_name: str | None = Field(default=None, description="Country name of the host.")
    city: str | None = Field(default=None, description="City of the host.")
    latitude: float | None = Field(default=None, description="Latitude of the host's location.")
    longitude: float | None = Field(default=None, description="Longitude of the host's location.")
    ports: list[int] = Field(default_factory=list, description="Open TCP/UDP ports on the host.")
    vulnerabilities: list[str] = Field(
        default_factory=list,
        description="CVE identifiers Shodan associates with the host.",
    )
    services: list[ShodanService] = Field(
        default_factory=list,
        description="Per-port service details (product / version / transport).",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Shodan tags (tor, vpn, c2, ...).",
    )
    last_update: str | None = Field(
        default=None,
        description="ISO-8601 timestamp of the last Shodan scan of this host.",
    )


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


@NodeRegistry.register
class ShodanHostLookupNode(Node[ShodanHostLookupInput, ShodanHostLookupOutput]):
    """Look up an IP on Shodan and return open ports / services / vulns / location."""

    meta = NodeMeta(
        id="integration.shodan.host_lookup",
        name="Shodan: Host Lookup",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
        description="Shodan host-info lookup. Returns open ports, detected services, "
        "vulnerabilities (CVE list), AS/ISP/org, geolocation, and Shodan tags.",
    )
    input_schema = ShodanHostLookupInput
    output_schema = ShodanHostLookupOutput
    manifest = SHODAN_MANIFEST
    capability_id = "host_lookup"

    async def run(
        self,
        input: ShodanHostLookupInput,
        ctx: NodeContext,
    ) -> ShodanHostLookupOutput:
        if _mock_mode_enabled():
            record = _MOCK_HOSTS.get(input.ip)
            if record is None:
                return ShodanHostLookupOutput(seen=False)
            data = dict(record)
            data["vulnerabilities"] = data.pop("vulns", [])
            return ShodanHostLookupOutput(seen=True, **data)
        raise NotImplementedError(
            "Shodan live API integration ships in Sprint 2 follow-up; "
            "set BTAGENT_MOCK_CONNECTORS=true to use mock fixtures."
        )
