"""End-to-end tests for the VirusTotal integration Nodes."""

from __future__ import annotations

import pytest

from btagent_engine import NodeContext, NodeRegistry, Runner
from btagent_engine.integrations.virustotal import (
    VirusTotalDomainLookupInput,
    VirusTotalDomainLookupNode,
    VirusTotalDomainLookupOutput,
    VirusTotalHashLookupInput,
    VirusTotalHashLookupNode,
    VirusTotalHashLookupOutput,
    VirusTotalIPLookupInput,
    VirusTotalIPLookupNode,
    VirusTotalIPLookupOutput,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_vt", org_id="org_default", investigation_id="inv_test")


@pytest.fixture(autouse=True)
def _enable_mock(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    yield


# ---------------------------------------------------------------------------
# IP lookup
# ---------------------------------------------------------------------------


async def test_virustotal_ip_lookup_returns_known_malicious_record():
    out = await Runner().execute(
        VirusTotalIPLookupNode(),
        VirusTotalIPLookupInput(ip="185.220.101.42"),
        _ctx(),
    )
    assert isinstance(out, VirusTotalIPLookupOutput)
    assert out.seen is True
    assert out.malicious >= 10
    assert out.reputation < 0
    assert "tor-exit-node" in out.categories


async def test_virustotal_ip_lookup_returns_not_seen_for_unknown_ip():
    out = await Runner().execute(
        VirusTotalIPLookupNode(),
        VirusTotalIPLookupInput(ip="203.0.113.99"),
        _ctx(),
    )
    assert out.seen is False
    assert out.malicious == 0
    assert out.categories == []


async def test_virustotal_ip_lookup_accepts_dict_payload_through_runner():
    out = await Runner().execute(
        VirusTotalIPLookupNode(),
        {"ip": "185.220.101.42"},
        _ctx(),
    )
    assert out.seen is True
    assert out.country == "DE"


async def test_virustotal_ip_lookup_raises_in_non_mock_mode(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    with pytest.raises(NotImplementedError, match="Sprint 2"):
        await VirusTotalIPLookupNode().run(
            VirusTotalIPLookupInput(ip="8.8.8.8"),
            _ctx(),
        )


# ---------------------------------------------------------------------------
# Domain lookup
# ---------------------------------------------------------------------------


async def test_virustotal_domain_lookup_returns_known_malicious_record():
    out = await Runner().execute(
        VirusTotalDomainLookupNode(),
        VirusTotalDomainLookupInput(domain="c2-server.xyz"),
        _ctx(),
    )
    assert isinstance(out, VirusTotalDomainLookupOutput)
    assert out.seen is True
    assert out.malicious >= 10
    assert "c2" in out.categories


async def test_virustotal_domain_lookup_returns_not_seen_for_unknown_domain():
    out = await Runner().execute(
        VirusTotalDomainLookupNode(),
        VirusTotalDomainLookupInput(domain="example.com"),
        _ctx(),
    )
    assert out.seen is False
    assert out.malicious == 0


async def test_virustotal_domain_lookup_raises_in_non_mock_mode(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    with pytest.raises(NotImplementedError, match="Sprint 2"):
        await VirusTotalDomainLookupNode().run(
            VirusTotalDomainLookupInput(domain="example.com"),
            _ctx(),
        )


# ---------------------------------------------------------------------------
# Hash lookup
# ---------------------------------------------------------------------------


async def test_virustotal_hash_lookup_returns_known_malicious_record():
    out = await Runner().execute(
        VirusTotalHashLookupNode(),
        VirusTotalHashLookupInput(
            hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        _ctx(),
    )
    assert isinstance(out, VirusTotalHashLookupOutput)
    assert out.seen is True
    assert out.malicious >= 40
    assert out.threat_label is not None
    assert "CobaltStrike" in out.malware_families


async def test_virustotal_hash_lookup_returns_not_seen_for_unknown_hash():
    out = await Runner().execute(
        VirusTotalHashLookupNode(),
        VirusTotalHashLookupInput(hash="0" * 64),
        _ctx(),
    )
    assert out.seen is False
    assert out.malicious == 0
    assert out.threat_label is None


async def test_virustotal_hash_lookup_raises_in_non_mock_mode(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    with pytest.raises(NotImplementedError, match="Sprint 2"):
        await VirusTotalHashLookupNode().run(
            VirusTotalHashLookupInput(hash="0" * 64),
            _ctx(),
        )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_virustotal_nodes_are_registered():
    assert NodeRegistry.get("integration.virustotal.ip_lookup") is VirusTotalIPLookupNode
    assert NodeRegistry.get("integration.virustotal.domain_lookup") is VirusTotalDomainLookupNode
    assert NodeRegistry.get("integration.virustotal.hash_lookup") is VirusTotalHashLookupNode
