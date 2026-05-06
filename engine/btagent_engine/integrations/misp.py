"""MISP integration nodes.

Two MISP nodes -- attribute search and event lookup -- following the
GreyNoise reference shape (see ``greynoise.py``):

* ``BTAGENT_MOCK_CONNECTORS=true`` returns realistic, deterministic
  mock fixtures with two pinned events plus a clean fall-through
  (empty result list / not-found event) for any other input.
* The production path raises ``NotImplementedError`` -- the real MISP
  REST client + credential vault wiring ships in a Sprint 2 follow-up.
  Failing loudly prevents a misconfigured prod env from silently
  returning mock data.
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


def _mock_mode_enabled() -> bool:
    """Resolve the mock-mode flag at call time so tests can flip it."""
    return os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Mock fixtures
# ---------------------------------------------------------------------------

_MOCK_EVENTS: dict[str, dict[str, Any]] = {
    "EVT-10042": {
        "event_id": "EVT-10042",
        "info": "CobaltStrike C2 Infrastructure - Operation ShadowStrike",
        "date": "2026-03-20",
        "threat_level": "High",
        "analysis": "Completed",
        "org": "ACME-CERT",
        "published": True,
        "timestamp": "2026-03-24T14:00:00Z",
        "tags": [
            "tlp:amber",
            'misp-galaxy:threat-actor="APT-Phantom"',
            'misp-galaxy:mitre-attack-pattern="T1059.001"',
            "cobalt-strike",
        ],
        "attributes": [
            {
                "id": "attr-100421",
                "type": "ip-dst",
                "category": "Network activity",
                "value": "185.220.101.42",
                "to_ids": True,
                "comment": "CobaltStrike C2 server",
            },
            {
                "id": "attr-100423",
                "type": "domain",
                "category": "Network activity",
                "value": "c2-server.xyz",
                "to_ids": True,
                "comment": "Primary C2 domain",
            },
            {
                "id": "attr-100425",
                "type": "sha256",
                "category": "Payload delivery",
                "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "to_ids": True,
                "comment": "CobaltStrike beacon payload",
            },
        ],
    },
    "EVT-10038": {
        "event_id": "EVT-10038",
        "info": "Brute Force Campaign Targeting VPN Infrastructure",
        "date": "2026-03-18",
        "threat_level": "Medium",
        "analysis": "Completed",
        "org": "ACME-CERT",
        "published": True,
        "timestamp": "2026-03-22T09:00:00Z",
        "tags": [
            "tlp:green",
            "brute-force",
            'misp-galaxy:mitre-attack-pattern="T1110.001"',
        ],
        "attributes": [
            {
                "id": "attr-100381",
                "type": "ip-src",
                "category": "Network activity",
                "value": "185.220.101.42",
                "to_ids": True,
                "comment": "Brute force source IP (Tor exit)",
            },
        ],
    },
}


# ---------------------------------------------------------------------------
# Schemas -- shared
# ---------------------------------------------------------------------------


class MISPAttribute(BaseModel):
    id: str = Field(..., description="MISP attribute ID.")
    type: str = Field(..., description="MISP attribute type (ip-src, ip-dst, domain, sha256, ...).")
    category: str = Field(..., description="MISP attribute category (Network activity, ...).")
    value: str = Field(..., description="Attribute value (the IOC itself).")
    to_ids: bool = Field(
        default=True,
        description="True if this attribute should be exported to IDS / detection systems.",
    )
    comment: str | None = Field(default=None, description="Analyst-supplied comment.")


class MISPAttributeMatch(BaseModel):
    attribute: MISPAttribute = Field(..., description="The matching attribute.")
    event_id: str = Field(..., description="ID of the event the attribute belongs to.")
    event_info: str = Field(..., description="Human-readable event title.")
    threat_level: str = Field(..., description="Event threat level (High / Medium / Low / ...).")
    tags: list[str] = Field(
        default_factory=list,
        description="Tags applied to the parent event (TLP, galaxies, ...).",
    )


# ---------------------------------------------------------------------------
# Schemas -- search_attribute
# ---------------------------------------------------------------------------


class MISPSearchAttributeInput(BaseModel):
    value: str = Field(
        ...,
        description="Attribute value to search for (IP, domain, hash, URL, ...).",
        examples=["185.220.101.42", "c2-server.xyz"],
    )
    type: str | None = Field(
        default=None,
        description="Optional MISP attribute type filter "
        "(ip-src, ip-dst, domain, sha256, url, ...).",
    )


class MISPSearchAttributeOutput(BaseModel):
    value_queried: str = Field(..., description="The value that was searched for.")
    type_filter: str | None = Field(
        default=None,
        description="The type filter applied to the search, or None for no filter.",
    )
    result_count: int = Field(default=0, description="Number of matching attributes.")
    results: list[MISPAttributeMatch] = Field(
        default_factory=list,
        description="Matching attributes with their event context.",
    )


# ---------------------------------------------------------------------------
# Schemas -- get_event
# ---------------------------------------------------------------------------


class MISPEvent(BaseModel):
    event_id: str = Field(..., description="MISP event ID.")
    info: str = Field(..., description="Human-readable event title.")
    date: str = Field(..., description="Event date (YYYY-MM-DD).")
    threat_level: str = Field(..., description="Event threat level (High / Medium / Low / ...).")
    analysis: str = Field(..., description="Analysis state (Initial / Ongoing / Completed).")
    org: str = Field(..., description="Owning organisation.")
    published: bool = Field(default=False, description="True if the event has been published.")
    timestamp: str | None = Field(
        default=None,
        description="ISO-8601 timestamp of the last event update.",
    )
    tags: list[str] = Field(default_factory=list, description="Tags applied to the event.")
    attributes: list[MISPAttribute] = Field(
        default_factory=list,
        description="All attributes that belong to the event.",
    )


class MISPGetEventInput(BaseModel):
    event_id: str = Field(
        ...,
        description="MISP event ID to fetch.",
        examples=["EVT-10042"],
    )


class MISPGetEventOutput(BaseModel):
    found: bool = Field(default=False, description="True if the event was found.")
    event: MISPEvent | None = Field(
        default=None,
        description="The full event with attributes; None if not found.",
    )


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


@NodeRegistry.register
class MISPSearchAttributeNode(Node[MISPSearchAttributeInput, MISPSearchAttributeOutput]):
    """Search MISP attributes by value (with optional type filter)."""

    meta = NodeMeta(
        id="integration.misp.search_attribute",
        name="MISP: Search Attribute",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
        description="Search MISP attributes by value with optional type filter. "
        "Returns matching attributes with their parent event context.",
    )
    input_schema = MISPSearchAttributeInput
    output_schema = MISPSearchAttributeOutput

    async def run(
        self,
        input: MISPSearchAttributeInput,
        ctx: NodeContext,
    ) -> MISPSearchAttributeOutput:
        if _mock_mode_enabled():
            matches: list[MISPAttributeMatch] = []
            for evt in _MOCK_EVENTS.values():
                for attr in evt["attributes"]:
                    if input.value not in attr["value"]:
                        continue
                    if input.type is not None and attr["type"] != input.type:
                        continue
                    matches.append(
                        MISPAttributeMatch(
                            attribute=MISPAttribute(**attr),
                            event_id=evt["event_id"],
                            event_info=evt["info"],
                            threat_level=evt["threat_level"],
                            tags=list(evt["tags"]),
                        )
                    )
            return MISPSearchAttributeOutput(
                value_queried=input.value,
                type_filter=input.type,
                result_count=len(matches),
                results=matches,
            )
        raise NotImplementedError(
            "MISP live API integration ships in Sprint 2 follow-up; "
            "set BTAGENT_MOCK_CONNECTORS=true to use mock fixtures."
        )


@NodeRegistry.register
class MISPGetEventNode(Node[MISPGetEventInput, MISPGetEventOutput]):
    """Fetch a full MISP event by ID, including all attributes."""

    meta = NodeMeta(
        id="integration.misp.get_event",
        name="MISP: Get Event",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
        description="Fetch a full MISP event by ID, including all attributes and tags.",
    )
    input_schema = MISPGetEventInput
    output_schema = MISPGetEventOutput

    async def run(
        self,
        input: MISPGetEventInput,
        ctx: NodeContext,
    ) -> MISPGetEventOutput:
        if _mock_mode_enabled():
            raw = _MOCK_EVENTS.get(input.event_id)
            if raw is None:
                return MISPGetEventOutput(found=False, event=None)
            event = MISPEvent(
                event_id=raw["event_id"],
                info=raw["info"],
                date=raw["date"],
                threat_level=raw["threat_level"],
                analysis=raw["analysis"],
                org=raw["org"],
                published=raw["published"],
                timestamp=raw.get("timestamp"),
                tags=list(raw["tags"]),
                attributes=[MISPAttribute(**a) for a in raw["attributes"]],
            )
            return MISPGetEventOutput(found=True, event=event)
        raise NotImplementedError(
            "MISP live API integration ships in Sprint 2 follow-up; "
            "set BTAGENT_MOCK_CONNECTORS=true to use mock fixtures."
        )
