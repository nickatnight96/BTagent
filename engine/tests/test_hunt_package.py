"""Tests for HuntPackageNode (UC-2.2, #105) — the compound generator."""

from __future__ import annotations

import pytest

from btagent_engine import NodeContext
from btagent_engine.reasoning import (
    HuntPackageInput,
    HuntPackageNode,
    HuntPackageOutput,
)
from btagent_shared.types.hunt import Backend

_ADVISORY = (
    "CISA advisory AA26-001: actor infrastructure includes 10.1.42.17 and "
    "evil-c2.example, distributing payloads via https://evil-c2.example/x. "
    "Observed hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855."
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_pkg", org_id="org_test")


async def test_full_hunt_package_from_advisory(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await HuntPackageNode().run(
        HuntPackageInput(
            text=_ADVISORY,
            source_label="AA26-001",
            backends=[Backend.SPLUNK, Backend.SIGMA],
        ),
        _ctx(),
    )
    assert isinstance(out, HuntPackageOutput)
    pkg = out.package
    assert pkg.source_label == "AA26-001"
    # extracted at least the IP, domain, URL, hash
    assert pkg.extracted_ioc_count >= 4
    # derived techniques from the indicators
    assert pkg.derived_techniques
    # retro-hunt ran: 10.1.42.17 is in the fixtures -> sighting/compromise
    assert pkg.retro_report is not None
    assert pkg.retro_report.compromise_suspected is True
    # pre-built queries per technique, for requested backends
    assert pkg.queries
    first_ttp = pkg.derived_techniques[0]
    assert Backend.SPLUNK in pkg.queries[first_ttp]
    # one Sigma draft per technique
    assert len(pkg.sigma_drafts) == len(pkg.derived_techniques)


async def test_clean_advisory_no_sightings(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await HuntPackageNode().run(
        HuntPackageInput(text="Indicator 203.0.113.255 only.", source_label="x"),
        _ctx(),
    )
    # 203.0.113.255 isn't in the fixtures -> no sighting
    assert out.package.retro_report.compromise_suspected is False
    assert out.package.extracted_ioc_count == 1


async def test_non_mock_mode_raises(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    with pytest.raises(NotImplementedError):
        await HuntPackageNode().run(HuntPackageInput(text=_ADVISORY), _ctx())
