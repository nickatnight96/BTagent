"""End-to-end tests for the Shodan integration Node."""

from __future__ import annotations

import pytest

from btagent_engine import NodeContext, NodeRegistry, Runner
from btagent_engine.integrations.shodan import (
    ShodanHostLookupInput,
    ShodanHostLookupNode,
    ShodanHostLookupOutput,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_shodan", org_id="org_default", investigation_id="inv_test")


@pytest.fixture(autouse=True)
def _enable_mock(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    yield


async def test_shodan_host_lookup_returns_known_malicious_record():
    out = await Runner().execute(
        ShodanHostLookupNode(),
        ShodanHostLookupInput(ip="185.220.101.42"),
        _ctx(),
    )
    assert isinstance(out, ShodanHostLookupOutput)
    assert out.seen is True
    assert out.country_code == "DE"
    assert 8443 in out.ports
    assert "CVE-2024-6387" in out.vulnerabilities
    assert any(s.product == "CobaltStrike Beacon" for s in out.services)
    assert "tor" in out.tags


async def test_shodan_host_lookup_returns_second_known_record():
    out = await Runner().execute(
        ShodanHostLookupNode(),
        ShodanHostLookupInput(ip="45.155.205.233"),
        _ctx(),
    )
    assert out.seen is True
    assert out.country_code == "RU"
    assert 4444 in out.ports
    assert any(s.product == "Metasploit" for s in out.services)


async def test_shodan_host_lookup_returns_not_seen_for_unknown_ip():
    out = await Runner().execute(
        ShodanHostLookupNode(),
        ShodanHostLookupInput(ip="203.0.113.99"),
        _ctx(),
    )
    assert out.seen is False
    assert out.ports == []
    assert out.vulnerabilities == []
    assert out.services == []


async def test_shodan_host_lookup_accepts_dict_payload_through_runner():
    out = await Runner().execute(
        ShodanHostLookupNode(),
        {"ip": "185.220.101.42"},
        _ctx(),
    )
    assert out.seen is True
    assert out.org == "Tor Exit Node Hosting GmbH"


def test_shodan_host_lookup_node_is_registered():
    assert NodeRegistry.get("integration.shodan.host_lookup") is ShodanHostLookupNode


async def test_shodan_host_lookup_raises_in_non_mock_mode(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    with pytest.raises(NotImplementedError, match="Sprint 2"):
        await ShodanHostLookupNode().run(
            ShodanHostLookupInput(ip="8.8.8.8"),
            _ctx(),
        )
