"""End-to-end test: the GreyNoise reference Node runs through the Runner."""

from __future__ import annotations

import os

import pytest

from btagent_engine import NodeContext, NodeRegistry, Runner
from btagent_engine.integrations.greynoise import (
    GreyNoiseLookupIPInput,
    GreyNoiseLookupIPNode,
    GreyNoiseLookupIPOutput,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_greynoise", org_id="org_default", investigation_id="inv_test")


@pytest.fixture(autouse=True)
def _enable_mock(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    yield


async def test_greynoise_node_returns_known_malicious_record():
    out = await Runner().execute(
        GreyNoiseLookupIPNode(),
        GreyNoiseLookupIPInput(ip="185.220.101.42"),
        _ctx(),
    )
    assert isinstance(out, GreyNoiseLookupIPOutput)
    assert out.seen is True
    assert out.classification == "malicious"
    assert out.noise is True
    assert "Tor Exit Node" in out.tags


async def test_greynoise_node_returns_known_benign_record():
    out = await Runner().execute(
        GreyNoiseLookupIPNode(),
        GreyNoiseLookupIPInput(ip="8.8.8.8"),
        _ctx(),
    )
    assert out.classification == "benign"
    assert out.riot is True


async def test_greynoise_node_returns_not_seen_for_unknown_ip():
    """Mock fall-through must be deterministic 'not seen', not random data."""
    out = await Runner().execute(
        GreyNoiseLookupIPNode(),
        GreyNoiseLookupIPInput(ip="203.0.113.99"),
        _ctx(),
    )
    assert out.seen is False
    assert out.classification is None


async def test_greynoise_node_accepts_dict_payload_through_runner():
    """Workflow runners pass payloads as dicts (from JSON / YAML) -- confirm
    the Runner validates them against the input schema."""
    out = await Runner().execute(
        GreyNoiseLookupIPNode(),
        {"ip": "8.8.8.8"},
        _ctx(),
    )
    assert out.classification == "benign"


def test_greynoise_node_is_registered():
    """Node registers itself via the @NodeRegistry.register decorator."""
    assert NodeRegistry.get("integration.greynoise.lookup_ip") is GreyNoiseLookupIPNode


async def test_greynoise_node_raises_in_non_mock_mode_until_sprint_2(monkeypatch):
    """Production path is intentionally NotImplementedError until Sprint 2
    wires the real API + credential vault. This protects against a
    misconfigured prod env silently falling through to mock fixtures."""
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    with pytest.raises(NotImplementedError, match="Sprint 2"):
        await GreyNoiseLookupIPNode().run(
            GreyNoiseLookupIPInput(ip="8.8.8.8"),
            _ctx(),
        )
