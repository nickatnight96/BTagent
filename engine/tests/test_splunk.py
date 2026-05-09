"""End-to-end tests for the Splunk Node.

Mirrors the GreyNoise reference test layout:
* Mock-mode happy path returns the documented fixture shape.
* Empty / unknown query returns the documented empty shape.
* Dict payload through Runner.execute validates the input schema.
* NotImplementedError raised when mock mode is disabled.
* The Node is reachable via NodeRegistry.
"""

from __future__ import annotations

import pytest

from btagent_engine import NodeContext, NodeRegistry, Runner
from btagent_engine.integrations.splunk import (
    SplunkSearchInput,
    SplunkSearchNode,
    SplunkSearchOutput,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_splunk", org_id="org_default", investigation_id="inv_test")


@pytest.fixture(autouse=True)
def _enable_mock(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    yield


async def test_splunk_search_returns_auth_events_for_auth_query():
    out = await Runner().execute(
        SplunkSearchNode(),
        SplunkSearchInput(query="index=authentication action=failure"),
        _ctx(),
    )
    assert isinstance(out, SplunkSearchOutput)
    assert out.count == 1
    assert out.events[0]["index"] == "authentication"
    assert out.events[0]["src_ip"] == "185.220.101.42"
    assert out.truncated is False


async def test_splunk_search_returns_default_events_for_other_queries():
    out = await Runner().execute(
        SplunkSearchNode(),
        SplunkSearchInput(query="index=network src_ip=10.1.42.17"),
        _ctx(),
    )
    assert out.count == 2
    assert all(e["index"] == "network" for e in out.events)


async def test_splunk_search_empty_query_returns_empty_shape():
    """Whitespace / empty queries fall through to the documented empty shape."""
    out = await Runner().execute(
        SplunkSearchNode(),
        SplunkSearchInput(query="   "),
        _ctx(),
    )
    assert out.events == []
    assert out.count == 0
    assert out.truncated is False


async def test_splunk_search_truncates_when_max_count_exceeded():
    out = await Runner().execute(
        SplunkSearchNode(),
        SplunkSearchInput(query="index=network", max_count=1),
        _ctx(),
    )
    assert out.count == 1
    assert out.truncated is True


async def test_splunk_search_accepts_dict_payload_through_runner():
    out = await Runner().execute(
        SplunkSearchNode(),
        {"query": "index=authentication"},
        _ctx(),
    )
    assert out.count == 1
    assert out.events[0]["sourcetype"] == "okta:log"


def test_splunk_search_node_is_registered():
    assert NodeRegistry.get("integration.splunk.search") is SplunkSearchNode


async def test_splunk_search_raises_in_non_mock_mode(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    with pytest.raises(NotImplementedError, match="Sprint 2"):
        await SplunkSearchNode().run(
            SplunkSearchInput(query="index=network"),
            _ctx(),
        )
