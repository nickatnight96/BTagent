"""End-to-end tests for the MISP integration Nodes."""

from __future__ import annotations

import pytest

from btagent_engine import NodeContext, NodeRegistry, Runner
from btagent_engine.integrations.misp import (
    MISPGetEventInput,
    MISPGetEventNode,
    MISPGetEventOutput,
    MISPSearchAttributeInput,
    MISPSearchAttributeNode,
    MISPSearchAttributeOutput,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_misp", org_id="org_default", investigation_id="inv_test")


@pytest.fixture(autouse=True)
def _enable_mock(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    yield


# ---------------------------------------------------------------------------
# search_attribute
# ---------------------------------------------------------------------------


async def test_misp_search_attribute_returns_matches_for_known_value():
    out = await Runner().execute(
        MISPSearchAttributeNode(),
        MISPSearchAttributeInput(value="185.220.101.42"),
        _ctx(),
    )
    assert isinstance(out, MISPSearchAttributeOutput)
    assert out.value_queried == "185.220.101.42"
    assert out.type_filter is None
    # The IP appears in both EVT-10042 (ip-dst) and EVT-10038 (ip-src).
    assert out.result_count == 2
    event_ids = {m.event_id for m in out.results}
    assert event_ids == {"EVT-10042", "EVT-10038"}


async def test_misp_search_attribute_filters_by_type():
    out = await Runner().execute(
        MISPSearchAttributeNode(),
        MISPSearchAttributeInput(value="185.220.101.42", type="ip-src"),
        _ctx(),
    )
    assert out.result_count == 1
    assert out.results[0].event_id == "EVT-10038"
    assert out.results[0].attribute.type == "ip-src"


async def test_misp_search_attribute_returns_empty_for_unknown_value():
    out = await Runner().execute(
        MISPSearchAttributeNode(),
        MISPSearchAttributeInput(value="203.0.113.99"),
        _ctx(),
    )
    assert out.result_count == 0
    assert out.results == []


async def test_misp_search_attribute_accepts_dict_payload_through_runner():
    out = await Runner().execute(
        MISPSearchAttributeNode(),
        {"value": "c2-server.xyz"},
        _ctx(),
    )
    assert out.result_count == 1
    assert out.results[0].attribute.type == "domain"


async def test_misp_search_attribute_raises_in_non_mock_mode(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    with pytest.raises(NotImplementedError, match="Sprint 2"):
        await MISPSearchAttributeNode().run(
            MISPSearchAttributeInput(value="anything"),
            _ctx(),
        )


# ---------------------------------------------------------------------------
# get_event
# ---------------------------------------------------------------------------


async def test_misp_get_event_returns_full_event_for_known_id():
    out = await Runner().execute(
        MISPGetEventNode(),
        MISPGetEventInput(event_id="EVT-10042"),
        _ctx(),
    )
    assert isinstance(out, MISPGetEventOutput)
    assert out.found is True
    assert out.event is not None
    assert out.event.event_id == "EVT-10042"
    assert out.event.threat_level == "High"
    assert "tlp:amber" in out.event.tags
    assert len(out.event.attributes) >= 1


async def test_misp_get_event_returns_not_found_for_unknown_id():
    out = await Runner().execute(
        MISPGetEventNode(),
        MISPGetEventInput(event_id="EVT-99999"),
        _ctx(),
    )
    assert out.found is False
    assert out.event is None


async def test_misp_get_event_accepts_dict_payload_through_runner():
    out = await Runner().execute(
        MISPGetEventNode(),
        {"event_id": "EVT-10038"},
        _ctx(),
    )
    assert out.found is True
    assert out.event is not None
    assert out.event.threat_level == "Medium"


async def test_misp_get_event_raises_in_non_mock_mode(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    with pytest.raises(NotImplementedError, match="Sprint 2"):
        await MISPGetEventNode().run(
            MISPGetEventInput(event_id="EVT-10042"),
            _ctx(),
        )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_misp_nodes_are_registered():
    assert NodeRegistry.get("integration.misp.search_attribute") is MISPSearchAttributeNode
    assert NodeRegistry.get("integration.misp.get_event") is MISPGetEventNode
