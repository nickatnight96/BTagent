"""VirusTotal integration nodes.

Three lookup nodes -- IP, domain, and file-hash -- following the
GreyNoise reference shape (see ``greynoise.py``):

* ``BTAGENT_MOCK_CONNECTORS=true`` returns realistic, deterministic
  mock fixtures with 1-2 known records plus a clean fall-through for
  any other input.
* The production path raises ``NotImplementedError`` -- the real
  VirusTotal v3 HTTP client + credential vault wiring ships in a
  Sprint 2 follow-up. Failing loudly prevents a misconfigured prod env
  from silently returning mock data.
* No imports from ``btagent_agents`` / ``btagent_backend``.
"""

from __future__ import annotations

import os

from pydantic import BaseModel, Field

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

_MOCK_IPS: dict[str, dict[str, object]] = {
    "185.220.101.42": {
        "reputation": -87,
        "malicious": 14,
        "suspicious": 2,
        "harmless": 6,
        "undetected": 62,
        "country": "DE",
        "as_owner": "Tor Exit Node Hosting GmbH",
        "categories": ["tor-exit-node", "c2-server", "brute-force"],
    },
    "45.155.205.233": {
        "reputation": -94,
        "malicious": 22,
        "suspicious": 5,
        "harmless": 6,
        "undetected": 41,
        "country": "RU",
        "as_owner": "ShadowNet LLC",
        "categories": ["c2-server", "cobalt-strike", "apt"],
    },
}

_MOCK_DOMAINS: dict[str, dict[str, object]] = {
    "c2-server.xyz": {
        "reputation": -91,
        "malicious": 18,
        "suspicious": 6,
        "harmless": 4,
        "undetected": 46,
        "registrar": "Namecheap Inc.",
        "categories": ["cobalt-strike", "c2", "apt"],
    },
    "suspicious-domain.ru": {
        "reputation": -72,
        "malicious": 11,
        "suspicious": 4,
        "harmless": 4,
        "undetected": 55,
        "registrar": "REG.RU LLC",
        "categories": ["phishing", "c2", "dga"],
    },
}

_MOCK_HASHES: dict[str, dict[str, object]] = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "malicious": 48,
        "suspicious": 3,
        "harmless": 0,
        "undetected": 21,
        "detection_ratio": "48/74",
        "threat_label": "trojan.cobaltstrike/agent",
        "malware_families": ["CobaltStrike", "Beacon"],
        "categories": ["trojan", "backdoor"],
    },
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2": {
        "malicious": 52,
        "suspicious": 4,
        "harmless": 0,
        "undetected": 18,
        "detection_ratio": "52/74",
        "threat_label": "trojan.generic/dropper",
        "malware_families": ["GenericDropper"],
        "categories": ["trojan", "dropper"],
    },
}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class VirusTotalIPLookupInput(BaseModel):
    ip: str = Field(
        ...,
        description="IPv4 / IPv6 address to look up on VirusTotal.",
        examples=["185.220.101.42", "8.8.8.8"],
    )


class VirusTotalIPLookupOutput(BaseModel):
    seen: bool = Field(
        default=False,
        description="True if VirusTotal has any record of this IP.",
    )
    reputation: int = Field(
        default=0,
        description="VirusTotal community reputation score; negative is bad.",
    )
    malicious: int = Field(default=0, description="Engines that flagged the IP as malicious.")
    suspicious: int = Field(default=0, description="Engines that flagged the IP as suspicious.")
    harmless: int = Field(default=0, description="Engines that flagged the IP as harmless.")
    undetected: int = Field(default=0, description="Engines that returned no opinion.")
    country: str | None = Field(default=None, description="ISO country code of the IP, if known.")
    as_owner: str | None = Field(
        default=None,
        description="Owner of the autonomous system the IP belongs to.",
    )
    categories: list[str] = Field(
        default_factory=list,
        description="VirusTotal tags / categories applied to the IP.",
    )


class VirusTotalDomainLookupInput(BaseModel):
    domain: str = Field(
        ...,
        description="Fully-qualified domain name to look up on VirusTotal.",
        examples=["c2-server.xyz", "example.com"],
    )


class VirusTotalDomainLookupOutput(BaseModel):
    seen: bool = Field(
        default=False,
        description="True if VirusTotal has any record of this domain.",
    )
    reputation: int = Field(
        default=0,
        description="VirusTotal community reputation score; negative is bad.",
    )
    malicious: int = Field(default=0, description="Engines that flagged the domain as malicious.")
    suspicious: int = Field(default=0, description="Engines that flagged the domain as suspicious.")
    harmless: int = Field(default=0, description="Engines that flagged the domain as harmless.")
    undetected: int = Field(default=0, description="Engines that returned no opinion.")
    registrar: str | None = Field(default=None, description="Registrar of record, if known.")
    categories: list[str] = Field(
        default_factory=list,
        description="VirusTotal tags / categories applied to the domain.",
    )


class VirusTotalHashLookupInput(BaseModel):
    hash: str = Field(
        ...,
        description="File hash (MD5, SHA1, or SHA256) to look up on VirusTotal.",
        examples=["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    )


class VirusTotalHashLookupOutput(BaseModel):
    seen: bool = Field(
        default=False,
        description="True if VirusTotal has any record of this hash.",
    )
    malicious: int = Field(default=0, description="Engines that flagged the file as malicious.")
    suspicious: int = Field(default=0, description="Engines that flagged the file as suspicious.")
    harmless: int = Field(default=0, description="Engines that flagged the file as harmless.")
    undetected: int = Field(default=0, description="Engines that returned no opinion.")
    detection_ratio: str | None = Field(
        default=None,
        description="Fraction in 'malicious/total' form, eg '48/74'.",
    )
    threat_label: str | None = Field(
        default=None,
        description="VirusTotal's suggested threat label, e.g. 'trojan.cobaltstrike/agent'.",
    )
    malware_families: list[str] = Field(
        default_factory=list,
        description="Named malware families detected.",
    )
    categories: list[str] = Field(
        default_factory=list,
        description="Threat categories (trojan, backdoor, ...).",
    )


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


@NodeRegistry.register
class VirusTotalIPLookupNode(Node[VirusTotalIPLookupInput, VirusTotalIPLookupOutput]):
    """Look up an IP on VirusTotal and return its reputation / detection stats."""

    meta = NodeMeta(
        id="integration.virustotal.ip_lookup",
        name="VirusTotal: Lookup IP",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
        description="VirusTotal IP reputation lookup. Returns engine detection counts, "
        "community reputation, AS owner, country, and applied categories.",
    )
    input_schema = VirusTotalIPLookupInput
    output_schema = VirusTotalIPLookupOutput

    async def run(
        self,
        input: VirusTotalIPLookupInput,
        ctx: NodeContext,
    ) -> VirusTotalIPLookupOutput:
        if _mock_mode_enabled():
            record = _MOCK_IPS.get(input.ip)
            if record is None:
                return VirusTotalIPLookupOutput(seen=False)
            return VirusTotalIPLookupOutput(seen=True, **record)
        raise NotImplementedError(
            "VirusTotal live API integration ships in Sprint 2 follow-up; "
            "set BTAGENT_MOCK_CONNECTORS=true to use mock fixtures."
        )


@NodeRegistry.register
class VirusTotalDomainLookupNode(Node[VirusTotalDomainLookupInput, VirusTotalDomainLookupOutput]):
    """Look up a domain on VirusTotal and return its reputation / detection stats."""

    meta = NodeMeta(
        id="integration.virustotal.domain_lookup",
        name="VirusTotal: Lookup Domain",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
        description="VirusTotal domain reputation lookup. Returns engine detection counts, "
        "community reputation, registrar, and applied categories.",
    )
    input_schema = VirusTotalDomainLookupInput
    output_schema = VirusTotalDomainLookupOutput

    async def run(
        self,
        input: VirusTotalDomainLookupInput,
        ctx: NodeContext,
    ) -> VirusTotalDomainLookupOutput:
        if _mock_mode_enabled():
            record = _MOCK_DOMAINS.get(input.domain)
            if record is None:
                return VirusTotalDomainLookupOutput(seen=False)
            return VirusTotalDomainLookupOutput(seen=True, **record)
        raise NotImplementedError(
            "VirusTotal live API integration ships in Sprint 2 follow-up; "
            "set BTAGENT_MOCK_CONNECTORS=true to use mock fixtures."
        )


@NodeRegistry.register
class VirusTotalHashLookupNode(Node[VirusTotalHashLookupInput, VirusTotalHashLookupOutput]):
    """Look up a file hash on VirusTotal and return its detection stats / labels."""

    meta = NodeMeta(
        id="integration.virustotal.hash_lookup",
        name="VirusTotal: Lookup File Hash",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
        description="VirusTotal file-hash lookup (MD5/SHA1/SHA256). Returns engine "
        "detection counts, detection ratio, suggested threat label, malware families, "
        "and threat categories.",
    )
    input_schema = VirusTotalHashLookupInput
    output_schema = VirusTotalHashLookupOutput

    async def run(
        self,
        input: VirusTotalHashLookupInput,
        ctx: NodeContext,
    ) -> VirusTotalHashLookupOutput:
        if _mock_mode_enabled():
            record = _MOCK_HASHES.get(input.hash)
            if record is None:
                return VirusTotalHashLookupOutput(seen=False)
            return VirusTotalHashLookupOutput(seen=True, **record)
        raise NotImplementedError(
            "VirusTotal live API integration ships in Sprint 2 follow-up; "
            "set BTAGENT_MOCK_CONNECTORS=true to use mock fixtures."
        )
