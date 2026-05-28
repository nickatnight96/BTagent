"""GreyNoise integration nodes.

This is the *reference* integration node implementation -- the Sprint 1
spike. It demonstrates:

* The Node ABC contract (input/output schemas, meta, run).
* Mock-mode pattern (BTAGENT_MOCK_CONNECTORS=true returns realistic
  fixtures; production mode is a placeholder for the real API call).
* Idempotent design: the same input always produces the same output
  in mock mode, which keeps replay deterministic.
* No imports from ``btagent_agents`` or ``btagent_backend`` -- the
  engine package must be standalone-shippable.

When Sprint 2 ports the rest of the connectors (Splunk, CrowdStrike,
Sentinel, Elastic, VirusTotal, Shodan, AbuseIPDB, MISP), each follows
this same shape: ``XLookupYNode``, ``XLookupYInput``, ``XLookupYOutput``.
"""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel, Field

from btagent_engine.integrations._manifests import GREYNOISE_MANIFEST
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
# Two pinned IPs for deterministic replay. The mock fall-through for any
# other IP returns a clean 'not seen' record so node tests don't need to
# special-case the dataset.

_MOCK_IPS: dict[str, dict[str, Any]] = {
    "185.220.101.42": {
        "seen": True,
        "classification": "malicious",
        "noise": True,
        "riot": False,
        "actor": "unknown",
        "tags": ["Tor Exit Node", "Brute Force SSH", "CobaltStrike C2"],
        "first_seen": "2025-11-10T00:00:00Z",
        "last_seen": "2026-03-26T06:00:00Z",
    },
    "8.8.8.8": {
        "seen": True,
        "classification": "benign",
        "noise": False,
        "riot": True,
        "actor": "Google Public DNS",
        "tags": ["dns"],
        "first_seen": "2014-10-29T00:00:00Z",
        "last_seen": "2026-04-30T12:00:00Z",
    },
}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class GreyNoiseLookupIPInput(BaseModel):
    ip: str = Field(
        ...,
        description="IPv4 / IPv6 address to look up.",
        examples=["185.220.101.42", "8.8.8.8"],
    )


class GreyNoiseLookupIPOutput(BaseModel):
    seen: bool = Field(
        default=False,
        description="True if GreyNoise has any record of this IP.",
    )
    classification: str | None = Field(
        default=None,
        description="One of 'malicious' / 'benign' / 'unknown' / None when not seen.",
    )
    noise: bool = Field(
        default=False,
        description="True if the IP is part of GreyNoise's internet-wide-noise set.",
    )
    riot: bool = Field(
        default=False,
        description="True if the IP is in GreyNoise's RIOT (rule-it-out) set "
        "of common benign services.",
    )
    actor: str | None = Field(
        default=None,
        description="Named actor / service operating from the IP, if known.",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="GreyNoise tags such as 'Tor Exit Node', 'Web Scanner', etc.",
    )
    first_seen: str | None = None
    last_seen: str | None = None


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


@NodeRegistry.register
class GreyNoiseLookupIPNode(Node[GreyNoiseLookupIPInput, GreyNoiseLookupIPOutput]):
    """Look up an IP on GreyNoise and return its noise / classification record."""

    meta = NodeMeta(
        id="integration.greynoise.lookup_ip",
        name="GreyNoise: Lookup IP",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
        description="Full IP context lookup on GreyNoise. Returns classification, "
        "noise / RIOT membership, tags, and first/last-seen timestamps.",
    )
    input_schema = GreyNoiseLookupIPInput
    output_schema = GreyNoiseLookupIPOutput
    manifest = GREYNOISE_MANIFEST
    capability_id = "lookup_ip"

    async def run(
        self,
        input: GreyNoiseLookupIPInput,
        ctx: NodeContext,
    ) -> GreyNoiseLookupIPOutput:
        if _mock_mode_enabled():
            record = _MOCK_IPS.get(input.ip)
            if record is None:
                return GreyNoiseLookupIPOutput(seen=False)
            return GreyNoiseLookupIPOutput(**record)

        # Production path: real GreyNoise API call. Out of scope for the
        # spike; Sprint 2 wires this through an HTTP client + the credential
        # vault. Until then, fail loudly so a misconfigured prod env doesn't
        # silently fall through to mock data.
        raise NotImplementedError(
            "GreyNoise live API integration ships in Sprint 2; "
            "set BTAGENT_MOCK_CONNECTORS=true to use mock fixtures."
        )
