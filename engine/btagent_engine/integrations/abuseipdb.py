"""AbuseIPDB integration node.

Single IP-check node following the GreyNoise reference shape (see
``greynoise.py``):

* ``BTAGENT_MOCK_CONNECTORS=true`` returns realistic, deterministic
  mock fixtures with two pinned IPs plus a clean fall-through for any
  other input.
* The production path raises ``NotImplementedError`` -- the real
  AbuseIPDB v2 HTTP client + credential vault wiring ships in a
  Sprint 2 follow-up. Failing loudly prevents a misconfigured prod env
  from silently returning mock data.
* No imports from ``btagent_agents`` / ``btagent_backend``.
"""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel, Field

from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)
from btagent_engine.integrations._manifests import ABUSEIPDB_MANIFEST


def _mock_mode_enabled() -> bool:
    """Resolve the mock-mode flag at call time so tests can flip it."""
    return os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Mock fixtures
# ---------------------------------------------------------------------------

_MOCK_IPS: dict[str, dict[str, Any]] = {
    "185.220.101.42": {
        "abuse_confidence_score": 100,
        "total_reports": 4872,
        "num_distinct_users": 1243,
        "country_code": "DE",
        "country_name": "Germany",
        "isp": "Tor Exit Node Hosting GmbH",
        "domain": "tor-hosting.de",
        "usage_type": "Data Center/Web Hosting/Transit",
        "is_tor": True,
        "is_whitelisted": False,
        "last_reported_at": "2026-03-26T07:55:00Z",
        "categories": ["Port Scan", "Brute-Force", "Hacking", "Web App Attack"],
    },
    "45.155.205.233": {
        "abuse_confidence_score": 97,
        "total_reports": 2156,
        "num_distinct_users": 687,
        "country_code": "RU",
        "country_name": "Russia",
        "isp": "ShadowNet LLC",
        "domain": "shadownet.ru",
        "usage_type": "Data Center/Web Hosting/Transit",
        "is_tor": False,
        "is_whitelisted": False,
        "last_reported_at": "2026-03-26T05:00:00Z",
        "categories": ["Hacking", "Malware Distribution", "Brute-Force"],
    },
}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class AbuseIPDBCheckInput(BaseModel):
    ip: str = Field(
        ...,
        description="IPv4 / IPv6 address to check on AbuseIPDB.",
        examples=["185.220.101.42", "8.8.8.8"],
    )
    max_age_days: int = Field(
        default=90,
        ge=1,
        le=365,
        description="Only consider reports newer than this many days (AbuseIPDB cap = 365).",
    )


class AbuseIPDBCheckOutput(BaseModel):
    seen: bool = Field(
        default=False,
        description="True if AbuseIPDB has any record of this IP.",
    )
    abuse_confidence_score: int = Field(
        default=0,
        ge=0,
        le=100,
        description="AbuseIPDB confidence score 0-100; higher is worse.",
    )
    total_reports: int = Field(default=0, description="Total abuse reports on file for this IP.")
    num_distinct_users: int = Field(
        default=0,
        description="Number of distinct users that have reported this IP.",
    )
    country_code: str | None = Field(default=None, description="ISO country code of the IP.")
    country_name: str | None = Field(default=None, description="Country name of the IP.")
    isp: str | None = Field(default=None, description="ISP for the IP.")
    domain: str | None = Field(default=None, description="Domain associated with the IP, if any.")
    usage_type: str | None = Field(
        default=None,
        description="AbuseIPDB usage classification (Data Center, ISP, ...).",
    )
    is_tor: bool = Field(default=False, description="True if the IP is a known Tor exit node.")
    is_whitelisted: bool = Field(
        default=False,
        description="True if the IP is in AbuseIPDB's whitelist.",
    )
    last_reported_at: str | None = Field(
        default=None,
        description="ISO-8601 timestamp of the most recent abuse report.",
    )
    categories: list[str] = Field(
        default_factory=list,
        description="Human-readable AbuseIPDB report categories aggregated for this IP.",
    )


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


@NodeRegistry.register
class AbuseIPDBCheckNode(Node[AbuseIPDBCheckInput, AbuseIPDBCheckOutput]):
    """Check an IP against AbuseIPDB and return its abuse-confidence record."""

    meta = NodeMeta(
        id="integration.abuseipdb.check",
        name="AbuseIPDB: Check IP",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
        description="AbuseIPDB IP reputation check. Returns abuse confidence score, "
        "total reports, country, ISP/domain, usage type, Tor membership, and "
        "report categories.",
    )
    input_schema = AbuseIPDBCheckInput
    output_schema = AbuseIPDBCheckOutput
    manifest = ABUSEIPDB_MANIFEST
    capability_id = "check"

    async def run(
        self,
        input: AbuseIPDBCheckInput,
        ctx: NodeContext,
    ) -> AbuseIPDBCheckOutput:
        if _mock_mode_enabled():
            # ``max_age_days`` does not change the mock fixtures (they're
            # already recent). Real implementation will pass it through to
            # the API as the ``maxAgeInDays`` query parameter.
            record = _MOCK_IPS.get(input.ip)
            if record is None:
                return AbuseIPDBCheckOutput(seen=False)
            return AbuseIPDBCheckOutput(seen=True, **record)
        raise NotImplementedError(
            "AbuseIPDB live API integration ships in Sprint 2 follow-up; "
            "set BTAGENT_MOCK_CONNECTORS=true to use mock fixtures."
        )
