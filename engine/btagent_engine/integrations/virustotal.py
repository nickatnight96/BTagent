"""VirusTotal integration nodes — **declaratively authored** (#101).

This connector is the proof of the declarative-connector pattern: none of
the three lookups contains request code. Each capability in
``VIRUSTOTAL_MANIFEST`` carries a
:class:`~btagent_shared.types.connector_routing.RoutingSpec` describing
the endpoint, the path/query params, the ``${secret:...}``-referenced API
key, the retry policy, and the JSON-path → output-field mapping. The
generic runner (:mod:`btagent_engine.integrations._declarative`) executes
it. Adding a fourth VirusTotal lookup is a manifest entry plus an
input/output model — no new request logic.

What is unchanged from the programmatic version:

* ``BTAGENT_MOCK_CONNECTORS=true`` (the default) returns deterministic
  fixtures for the same two IPs / two domains / two hashes, with a clean
  "not seen" fall-through for anything else, and the same output shapes.
  The fixtures now model the **VirusTotal v3 response envelope** and flow
  through the declared response mapping, so mock runs exercise the real
  spec instead of a parallel code path.
* The production path still refuses to egress: the routing specs ship
  with ``live_egress_approved=False``, so turning mock mode off raises
  ``NotImplementedError`` exactly as before (the message now names the
  live-egress gate rather than "Sprint 2").
* Policy is untouched. Both nodes still declare ``manifest`` +
  ``capability_id``, so ``ConnectorPolicyMiddleware`` applies the
  capability's ``tlp_egress`` / ``hitl_required`` gates before ``run()``
  is entered. Declarative authoring changes *how the request is built*,
  never *whether the call is allowed*.
* No imports from ``btagent_agents`` / ``btagent_backend``.
"""

from __future__ import annotations

from typing import Any

from btagent_shared.types.config import TLP
from btagent_shared.types.connector import (
    AuthStyle,
    ConnectorManifest,
    CostClass,
    CredentialType,
    OCSFEventClass,
    ParamLocation,
    QueryCapability,
    RequestParam,
    ResponseMapping,
    RetryPolicy,
    RoutingAuth,
    RoutingSpec,
    TransportKind,
)
from pydantic import BaseModel, Field

from btagent_engine.integrations._declarative import (
    DeclarativeConnector,
    HTTPRequest,
    HTTPResponse,
)
from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)

# ---------------------------------------------------------------------------
# Routing — the declarative half of the connector (#101)
# ---------------------------------------------------------------------------

VT_API_BASE = "https://www.virustotal.com/api/v3"

#: VirusTotal authenticates with a bare API key in the ``x-apikey`` header.
#: The manifest stores a *reference*; the runner resolves it at call time
#: and scrubs the resolved value out of logs and errors.
_VT_AUTH = RoutingAuth(
    style=AuthStyle.API_KEY_HEADER,
    header="x-apikey",
    secret_ref="${env:VIRUSTOTAL_API_KEY}",
)

#: VT rate-limits the public tier hard (4 req/min), so back off generously.
_VT_RETRY = RetryPolicy(
    max_attempts=3,
    backoff_initial_ms=500,
    backoff_multiplier=2.0,
    backoff_max_ms=8_000,
    retry_on_status=[429, 500, 502, 503, 504],
)

#: Detection counters live in the same place for every VT object type.
_STATS_FIELDS = {
    "malicious": "last_analysis_stats.malicious",
    "suspicious": "last_analysis_stats.suspicious",
    "harmless": "last_analysis_stats.harmless",
    "undetected": "last_analysis_stats.undetected",
}

VT_IP_ROUTING = RoutingSpec(
    base_url=VT_API_BASE,
    path="/ip_addresses/{ip}",
    params=[RequestParam(name="ip", source="ip", location=ParamLocation.PATH)],
    auth=_VT_AUTH,
    retry=_VT_RETRY,
    response=ResponseMapping(
        root="data.attributes",
        fields={
            **_STATS_FIELDS,
            "reputation": "reputation",
            "country": "country",
            "as_owner": "as_owner",
            "categories": "tags",
        },
        constants={"seen": True},
        # VT answers 404 for an indicator it has never seen — that's a
        # clean "no record", not a connector failure.
        not_found_statuses=[404],
        not_found_output={"seen": False},
    ),
)

VT_DOMAIN_ROUTING = RoutingSpec(
    base_url=VT_API_BASE,
    path="/domains/{domain}",
    params=[RequestParam(name="domain", source="domain", location=ParamLocation.PATH)],
    auth=_VT_AUTH,
    retry=_VT_RETRY,
    response=ResponseMapping(
        root="data.attributes",
        fields={
            **_STATS_FIELDS,
            "reputation": "reputation",
            "registrar": "registrar",
            "categories": "tags",
        },
        constants={"seen": True},
        not_found_statuses=[404],
        not_found_output={"seen": False},
    ),
)

VT_HASH_ROUTING = RoutingSpec(
    base_url=VT_API_BASE,
    path="/files/{hash}",
    params=[RequestParam(name="hash", source="hash", location=ParamLocation.PATH)],
    auth=_VT_AUTH,
    retry=_VT_RETRY,
    response=ResponseMapping(
        root="data.attributes",
        fields={
            **_STATS_FIELDS,
            "threat_label": "popular_threat_classification.suggested_threat_label",
            "malware_families": "popular_threat_classification.popular_threat_name[*].value",
            "categories": "tags",
            # Carried through so the node can render VT's "48/74" ratio; the
            # denominator is the sum of every analysis bucket, which is how
            # VT's own UI computes it.
            "analysis_stats": "last_analysis_stats",
        },
        constants={"seen": True},
        not_found_statuses=[404],
        not_found_output={"seen": False},
    ),
)


# ---------------------------------------------------------------------------
# Connector manifest — VirusTotal (Layer 3 of the connector strategy, #100)
# ---------------------------------------------------------------------------

VIRUSTOTAL_MANIFEST = ConnectorManifest(
    name="virustotal",
    version="0.2.0",
    description="VirusTotal v3 — IP / domain / file-hash reputation and detection counts.",
    transport=TransportKind.HTTP_REST,
    auth=CredentialType.API_KEY,
    queries=[
        QueryCapability(
            id="ip_lookup",
            description="Reputation + detection stats for an IPv4 / IPv6 address.",
            ocsf_emits=[OCSFEventClass.THREAT_INTELLIGENCE],
            tlp_egress=TLP.AMBER,
            cost_class=CostClass.MODERATE,
            hitl_required=False,
            routing=VT_IP_ROUTING,
        ),
        QueryCapability(
            id="domain_lookup",
            description="Reputation + detection stats for a domain.",
            ocsf_emits=[OCSFEventClass.THREAT_INTELLIGENCE],
            tlp_egress=TLP.AMBER,
            cost_class=CostClass.MODERATE,
            hitl_required=False,
            routing=VT_DOMAIN_ROUTING,
        ),
        QueryCapability(
            id="hash_lookup",
            description="Reputation + detection stats for a file hash (MD5 / SHA1 / SHA256).",
            ocsf_emits=[OCSFEventClass.THREAT_INTELLIGENCE],
            tlp_egress=TLP.AMBER,
            cost_class=CostClass.MODERATE,
            hitl_required=False,
            routing=VT_HASH_ROUTING,
        ),
    ],
)


# ---------------------------------------------------------------------------
# Mock fixtures — shaped as real VirusTotal v3 API responses
# ---------------------------------------------------------------------------
# Same two IPs / two domains / two hashes as the programmatic version, so
# downstream fixtures and UAT expectations are unchanged. They are now
# expressed in the vendor's envelope and mapped by the routing spec.

_VT_IP_ATTRIBUTES: dict[str, dict[str, Any]] = {
    "185.220.101.42": {
        "reputation": -87,
        "last_analysis_stats": {
            "malicious": 14,
            "suspicious": 2,
            "harmless": 6,
            "undetected": 62,
        },
        "country": "DE",
        "as_owner": "Tor Exit Node Hosting GmbH",
        "tags": ["tor-exit-node", "c2-server", "brute-force"],
    },
    "45.155.205.233": {
        "reputation": -94,
        "last_analysis_stats": {
            "malicious": 22,
            "suspicious": 5,
            "harmless": 6,
            "undetected": 41,
        },
        "country": "RU",
        "as_owner": "ShadowNet LLC",
        "tags": ["c2-server", "cobalt-strike", "apt"],
    },
}

_VT_DOMAIN_ATTRIBUTES: dict[str, dict[str, Any]] = {
    "c2-server.xyz": {
        "reputation": -91,
        "last_analysis_stats": {
            "malicious": 18,
            "suspicious": 6,
            "harmless": 4,
            "undetected": 46,
        },
        "registrar": "Namecheap Inc.",
        "tags": ["cobalt-strike", "c2", "apt"],
    },
    "suspicious-domain.ru": {
        "reputation": -72,
        "last_analysis_stats": {
            "malicious": 11,
            "suspicious": 4,
            "harmless": 4,
            "undetected": 55,
        },
        "registrar": "REG.RU LLC",
        "tags": ["phishing", "c2", "dga"],
    },
}

_VT_FILE_ATTRIBUTES: dict[str, dict[str, Any]] = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "last_analysis_stats": {
            "malicious": 48,
            "suspicious": 3,
            "harmless": 0,
            "undetected": 21,
            "type-unsupported": 2,
        },
        "popular_threat_classification": {
            "suggested_threat_label": "trojan.cobaltstrike/agent",
            "popular_threat_name": [
                {"value": "CobaltStrike", "count": 31},
                {"value": "Beacon", "count": 18},
            ],
        },
        "tags": ["trojan", "backdoor"],
    },
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2": {
        "last_analysis_stats": {
            "malicious": 52,
            "suspicious": 4,
            "harmless": 0,
            "undetected": 18,
        },
        "popular_threat_classification": {
            "suggested_threat_label": "trojan.generic/dropper",
            "popular_threat_name": [{"value": "GenericDropper", "count": 26}],
        },
        "tags": ["trojan", "dropper"],
    },
}

_VT_COLLECTIONS: dict[str, tuple[str, dict[str, dict[str, Any]]]] = {
    "ip_addresses": ("ip_address", _VT_IP_ATTRIBUTES),
    "domains": ("domain", _VT_DOMAIN_ATTRIBUTES),
    "files": ("file", _VT_FILE_ATTRIBUTES),
}

_VT_NOT_FOUND = {
    "error": {"code": "NotFoundError", "message": "Resource not found."},
}


def virustotal_mock_sender(request: HTTPRequest) -> HTTPResponse:
    """Stand-in for the VirusTotal v3 API.

    Answers the same request objects the live sender would receive, so
    mock runs exercise the declared routing spec end-to-end — path
    templating, auth placement, status handling, and response mapping —
    without a single byte of network egress.
    """
    segments = [s for s in request.url.removeprefix(VT_API_BASE).split("/") if s]
    if len(segments) != 2:
        return HTTPResponse(status_code=404, json_body=_VT_NOT_FOUND)

    collection, identifier = segments
    entry = _VT_COLLECTIONS.get(collection)
    if entry is None:
        return HTTPResponse(status_code=404, json_body=_VT_NOT_FOUND)

    object_type, table = entry
    attributes = table.get(identifier)
    if attributes is None:
        return HTTPResponse(status_code=404, json_body=_VT_NOT_FOUND)

    return HTTPResponse(
        status_code=200,
        json_body={"data": {"id": identifier, "type": object_type, "attributes": attributes}},
    )


_VT = DeclarativeConnector(VIRUSTOTAL_MANIFEST, mock_sender=virustotal_mock_sender)


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


def _detection_ratio(stats: dict[str, Any] | None, malicious: int) -> str | None:
    """Render VT's 'malicious/total' ratio from the analysis-stats bucket."""
    if not isinstance(stats, dict):
        return None
    total = sum(value for value in stats.values() if isinstance(value, int))
    return f"{malicious}/{total}" if total else None


# ---------------------------------------------------------------------------
# Nodes — no request code, just the declarative call + output shaping
# ---------------------------------------------------------------------------


@NodeRegistry.register
class VirusTotalIPLookupNode(Node[VirusTotalIPLookupInput, VirusTotalIPLookupOutput]):
    """Look up an IP on VirusTotal and return its reputation / detection stats."""

    meta = NodeMeta(
        id="integration.virustotal.ip_lookup",
        name="VirusTotal: Lookup IP",
        version="0.2.0",
        category=NodeCategory.INTEGRATION,
        description="VirusTotal IP reputation lookup. Returns engine detection counts, "
        "community reputation, AS owner, country, and applied categories.",
    )
    input_schema = VirusTotalIPLookupInput
    output_schema = VirusTotalIPLookupOutput
    manifest = VIRUSTOTAL_MANIFEST
    capability_id = "ip_lookup"

    async def run(
        self,
        input: VirusTotalIPLookupInput,
        ctx: NodeContext,
    ) -> VirusTotalIPLookupOutput:
        mapped = await _VT.execute("ip_lookup", input.model_dump())
        return VirusTotalIPLookupOutput(**mapped)


@NodeRegistry.register
class VirusTotalDomainLookupNode(Node[VirusTotalDomainLookupInput, VirusTotalDomainLookupOutput]):
    """Look up a domain on VirusTotal and return its reputation / detection stats."""

    meta = NodeMeta(
        id="integration.virustotal.domain_lookup",
        name="VirusTotal: Lookup Domain",
        version="0.2.0",
        category=NodeCategory.INTEGRATION,
        description="VirusTotal domain reputation lookup. Returns engine detection counts, "
        "community reputation, registrar, and applied categories.",
    )
    input_schema = VirusTotalDomainLookupInput
    output_schema = VirusTotalDomainLookupOutput
    manifest = VIRUSTOTAL_MANIFEST
    capability_id = "domain_lookup"

    async def run(
        self,
        input: VirusTotalDomainLookupInput,
        ctx: NodeContext,
    ) -> VirusTotalDomainLookupOutput:
        mapped = await _VT.execute("domain_lookup", input.model_dump())
        return VirusTotalDomainLookupOutput(**mapped)


@NodeRegistry.register
class VirusTotalHashLookupNode(Node[VirusTotalHashLookupInput, VirusTotalHashLookupOutput]):
    """Look up a file hash on VirusTotal and return its detection stats / labels."""

    meta = NodeMeta(
        id="integration.virustotal.hash_lookup",
        name="VirusTotal: Lookup File Hash",
        version="0.2.0",
        category=NodeCategory.INTEGRATION,
        description="VirusTotal file-hash lookup (MD5/SHA1/SHA256). Returns engine "
        "detection counts, detection ratio, suggested threat label, malware families, "
        "and threat categories.",
    )
    input_schema = VirusTotalHashLookupInput
    output_schema = VirusTotalHashLookupOutput
    manifest = VIRUSTOTAL_MANIFEST
    capability_id = "hash_lookup"

    async def run(
        self,
        input: VirusTotalHashLookupInput,
        ctx: NodeContext,
    ) -> VirusTotalHashLookupOutput:
        mapped = await _VT.execute("hash_lookup", input.model_dump())
        stats = mapped.pop("analysis_stats", None)
        ratio = _detection_ratio(stats, int(mapped.get("malicious", 0)))
        if ratio is not None:
            mapped["detection_ratio"] = ratio
        return VirusTotalHashLookupOutput(**mapped)
