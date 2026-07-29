"""VirusTotal: the proof connector for declarative authoring (#101).

Two things are proved here.

1. **Parity.** The pinned dicts below are the outputs the programmatic
   VirusTotal nodes produced before the conversion, field for field. If
   the routing spec or the fixtures drift, these fail.
2. **No bypass.** The declarative connector is still gated by
   ``ConnectorPolicyMiddleware`` (TLP egress), still refuses live egress
   while ``routing.live_egress_approved`` is False, and still performs
   zero network I/O in mock mode.
"""

from __future__ import annotations

import pytest
from btagent_shared.types.config import TLP
from btagent_shared.types.connector_routing import AuthStyle
from btagent_shared.utils.secrets import is_secret_reference

from btagent_engine import NodeContext, Runner
from btagent_engine.integrations import _declarative
from btagent_engine.integrations._declarative import HTTPRequest, HTTPResponse
from btagent_engine.integrations.virustotal import (
    VIRUSTOTAL_MANIFEST,
    VT_API_BASE,
    VirusTotalDomainLookupInput,
    VirusTotalDomainLookupNode,
    VirusTotalHashLookupInput,
    VirusTotalHashLookupNode,
    VirusTotalIPLookupInput,
    VirusTotalIPLookupNode,
    virustotal_mock_sender,
)
from btagent_engine.middleware import ConnectorPolicyMiddleware, ConnectorPolicyViolation

# --------------------------------------------------------------------------- #
# Pre-conversion outputs, pinned verbatim
# --------------------------------------------------------------------------- #

PARITY_IP = {
    "185.220.101.42": {
        "seen": True,
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
        "seen": True,
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

PARITY_DOMAIN = {
    "c2-server.xyz": {
        "seen": True,
        "reputation": -91,
        "malicious": 18,
        "suspicious": 6,
        "harmless": 4,
        "undetected": 46,
        "registrar": "Namecheap Inc.",
        "categories": ["cobalt-strike", "c2", "apt"],
    },
    "suspicious-domain.ru": {
        "seen": True,
        "reputation": -72,
        "malicious": 11,
        "suspicious": 4,
        "harmless": 4,
        "undetected": 55,
        "registrar": "REG.RU LLC",
        "categories": ["phishing", "c2", "dga"],
    },
}

PARITY_HASH = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "seen": True,
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
        "seen": True,
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

NOT_SEEN_IP = {
    "seen": False,
    "reputation": 0,
    "malicious": 0,
    "suspicious": 0,
    "harmless": 0,
    "undetected": 0,
    "country": None,
    "as_owner": None,
    "categories": [],
}


@pytest.fixture(autouse=True)
def _mock_only(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")

    async def _boom(request: HTTPRequest) -> HTTPResponse:  # pragma: no cover
        raise AssertionError(f"live HTTP egress attempted: {request.method} {request.url}")

    monkeypatch.setattr(_declarative, "_httpx_sender", _boom)
    yield


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_vt", org_id="org_default", investigation_id="inv_test")


# --------------------------------------------------------------------------- #
# Parity with the programmatic implementation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("ip", sorted(PARITY_IP))
async def test_ip_lookup_output_is_identical_to_the_programmatic_version(ip):
    out = await VirusTotalIPLookupNode().run(VirusTotalIPLookupInput(ip=ip), _ctx())
    assert out.model_dump() == PARITY_IP[ip]


@pytest.mark.parametrize("domain", sorted(PARITY_DOMAIN))
async def test_domain_lookup_output_is_identical_to_the_programmatic_version(domain):
    out = await VirusTotalDomainLookupNode().run(VirusTotalDomainLookupInput(domain=domain), _ctx())
    assert out.model_dump() == PARITY_DOMAIN[domain]


@pytest.mark.parametrize("file_hash", sorted(PARITY_HASH))
async def test_hash_lookup_output_is_identical_to_the_programmatic_version(file_hash):
    out = await VirusTotalHashLookupNode().run(VirusTotalHashLookupInput(hash=file_hash), _ctx())
    assert out.model_dump() == PARITY_HASH[file_hash]


async def test_unknown_indicator_maps_the_404_to_a_clean_not_seen_record():
    out = await VirusTotalIPLookupNode().run(VirusTotalIPLookupInput(ip="203.0.113.99"), _ctx())
    assert out.model_dump() == NOT_SEEN_IP


async def test_unknown_hash_has_no_detection_ratio():
    out = await VirusTotalHashLookupNode().run(VirusTotalHashLookupInput(hash="0" * 64), _ctx())
    assert out.seen is False
    assert out.detection_ratio is None
    assert out.malware_families == []


# --------------------------------------------------------------------------- #
# The manifest is now the connector definition
# --------------------------------------------------------------------------- #


def test_every_virustotal_capability_is_declarative():
    declarative = {c.id for c in VIRUSTOTAL_MANIFEST.declarative_capabilities()}
    assert declarative == {"ip_lookup", "domain_lookup", "hash_lookup"}


def test_routing_declares_the_real_virustotal_v3_endpoints():
    paths = {
        cap.id: cap.routing.path for cap in VIRUSTOTAL_MANIFEST.queries if cap.routing is not None
    }
    assert paths == {
        "ip_lookup": "/ip_addresses/{ip}",
        "domain_lookup": "/domains/{domain}",
        "hash_lookup": "/files/{hash}",
    }
    for cap in VIRUSTOTAL_MANIFEST.queries:
        assert cap.routing.base_url == VT_API_BASE
        assert cap.routing.base_url.startswith("https://")


def test_credential_is_a_reference_never_material():
    for cap in VIRUSTOTAL_MANIFEST.queries:
        auth = cap.routing.auth
        assert auth.style is AuthStyle.API_KEY_HEADER
        assert auth.header == "x-apikey"
        assert is_secret_reference(auth.secret_ref)


def test_live_egress_stays_gated_until_reviewed():
    for cap in VIRUSTOTAL_MANIFEST.queries:
        assert cap.routing.live_egress_approved is False


def test_capabilities_keep_their_policy_declarations():
    """The conversion must not have relaxed a single policy field."""
    for cap in VIRUSTOTAL_MANIFEST.queries:
        assert cap.tlp_egress is TLP.AMBER
        assert cap.hitl_required is False


# --------------------------------------------------------------------------- #
# Policy still gates the declarative path
# --------------------------------------------------------------------------- #


async def test_tlp_gate_blocks_before_any_request_is_built(monkeypatch):
    calls: list[HTTPRequest] = []

    def _counting_sender(request: HTTPRequest) -> HTTPResponse:
        calls.append(request)
        return virustotal_mock_sender(request)

    monkeypatch.setattr("btagent_engine.integrations.virustotal._VT._mock_sender", _counting_sender)

    runner = Runner([ConnectorPolicyMiddleware(active_tlp=TLP.RED)])
    with pytest.raises(ConnectorPolicyViolation):
        await runner.execute(
            VirusTotalIPLookupNode(), VirusTotalIPLookupInput(ip="185.220.101.42"), _ctx()
        )

    assert calls == [], "AMBER capability under a RED context must not reach the HTTP runner"


async def test_policy_allows_the_call_and_records_capability_metadata(monkeypatch):
    runner = Runner([ConnectorPolicyMiddleware(active_tlp=TLP.AMBER)])
    ctx = _ctx()
    out = await runner.execute(
        VirusTotalIPLookupNode(), VirusTotalIPLookupInput(ip="185.220.101.42"), ctx
    )

    assert out.seen is True
    assert ctx.metadata["connector.name"] == "virustotal"
    assert ctx.metadata["connector.capability_id"] == "ip_lookup"


# --------------------------------------------------------------------------- #
# The mock sender behaves like the vendor
# --------------------------------------------------------------------------- #


def test_mock_sender_answers_404_for_an_unknown_collection():
    response = virustotal_mock_sender(HTTPRequest(method="GET", url=f"{VT_API_BASE}/urls/abc"))
    assert response.status_code == 404


def test_mock_sender_returns_the_vendor_envelope():
    response = virustotal_mock_sender(
        HTTPRequest(method="GET", url=f"{VT_API_BASE}/ip_addresses/185.220.101.42")
    )
    assert response.status_code == 200
    assert response.json_body["data"]["type"] == "ip_address"
    assert response.json_body["data"]["attributes"]["last_analysis_stats"]["malicious"] == 14
