"""End-to-end tests for the CrowdStrike Nodes (event_search + list_detections + isolate_host)."""

from __future__ import annotations

import pytest

from btagent_engine import NodeContext, NodeRegistry, Runner
from btagent_engine.integrations.crowdstrike import (
    CrowdStrikeEventSearchInput,
    CrowdStrikeEventSearchNode,
    CrowdStrikeEventSearchOutput,
    CrowdStrikeIsolateHostInput,
    CrowdStrikeIsolateHostNode,
    CrowdStrikeIsolateHostOutput,
    CrowdStrikeListDetectionsInput,
    CrowdStrikeListDetectionsNode,
    CrowdStrikeListDetectionsOutput,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_cs", org_id="org_default", investigation_id="inv_test")


@pytest.fixture(autouse=True)
def _enable_mock(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    yield


# ---------------------------------------------------------------------------
# event_search
# ---------------------------------------------------------------------------


async def test_event_search_returns_events_default_lookback():
    out = await Runner().execute(
        CrowdStrikeEventSearchNode(),
        CrowdStrikeEventSearchInput(query="#event_simpleName=ProcessRollup2"),
        _ctx(),
    )
    assert isinstance(out, CrowdStrikeEventSearchOutput)
    # At least the two recent ProcessRollup2 fixtures are within 24h.
    assert out.count >= 1
    assert len(out.events) == out.count
    # Each event carries the expected LogScale / Falcon fields.
    first = out.events[0]
    assert first["event_simpleName"] == "ProcessRollup2"
    assert "ComputerName" in first
    assert "UserName" in first
    assert "SHA256HashData" in first
    assert "CommandLine" in first


async def test_event_search_respects_max_events_cap():
    out = await Runner().execute(
        CrowdStrikeEventSearchNode(),
        CrowdStrikeEventSearchInput(query="#event_simpleName=ProcessRollup2", max_events=1),
        _ctx(),
    )
    assert out.count == 1
    assert len(out.events) == 1
    assert out.truncated is True


async def test_event_search_lookback_filters_old_events():
    """The lookback window filters events older than the requested hours.

    Mock fixture ages: event 1 = ~30 min, event 2 = ~90 min, event 3 = ~49 h.
    A 2h window sees events 1 and 2; the 49h-old event is excluded.
    A 72h window sees all three.
    """
    out_2h = await Runner().execute(
        CrowdStrikeEventSearchNode(),
        CrowdStrikeEventSearchInput(query="#event_simpleName=ProcessRollup2", lookback_hours=2),
        _ctx(),
    )
    assert out_2h.count == 2, f"expected 2 events in 2h window, got {out_2h.count}"

    out_72h = await Runner().execute(
        CrowdStrikeEventSearchNode(),
        CrowdStrikeEventSearchInput(query="#event_simpleName=ProcessRollup2", lookback_hours=72),
        _ctx(),
    )
    assert out_72h.count == 3, f"expected all 3 events in 72h window, got {out_72h.count}"
    assert out_72h.truncated is False


async def test_event_search_truncated_false_when_under_cap():
    out = await Runner().execute(
        CrowdStrikeEventSearchNode(),
        CrowdStrikeEventSearchInput(query="#event_simpleName=ProcessRollup2", max_events=1000),
        _ctx(),
    )
    assert out.truncated is False


def test_event_search_node_is_registered():
    # NodeRegistry.all() returns a mappingproxy keyed by node id.
    all_ids = set(NodeRegistry.all().keys())
    assert "integration.crowdstrike.event_search" in all_ids
    assert NodeRegistry.get("integration.crowdstrike.event_search") is CrowdStrikeEventSearchNode


async def test_event_search_raises_in_non_mock_mode(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    with pytest.raises(NotImplementedError, match="Sprint 4"):
        await CrowdStrikeEventSearchNode().run(
            CrowdStrikeEventSearchInput(query="#event_simpleName=ProcessRollup2"),
            _ctx(),
        )


# ---------------------------------------------------------------------------
# list_detections
# ---------------------------------------------------------------------------


async def test_list_detections_returns_all_when_severity_is_all():
    out = await Runner().execute(
        CrowdStrikeListDetectionsNode(),
        CrowdStrikeListDetectionsInput(severity="all"),
        _ctx(),
    )
    assert isinstance(out, CrowdStrikeListDetectionsOutput)
    assert out.count == 2
    assert out.detections[0]["severity"] in {"critical", "high", "medium", "low"}


async def test_list_detections_filters_by_severity_floor():
    out = await Runner().execute(
        CrowdStrikeListDetectionsNode(),
        CrowdStrikeListDetectionsInput(severity="critical"),
        _ctx(),
    )
    assert out.count == 1
    assert out.detections[0]["max_severity"] >= 90


async def test_list_detections_unknown_severity_returns_empty_shape():
    """Unknown severity strings fall through to the documented empty shape."""
    out = await Runner().execute(
        CrowdStrikeListDetectionsNode(),
        CrowdStrikeListDetectionsInput(severity="unknown-bucket"),
        _ctx(),
    )
    assert out.detections == []
    assert out.count == 0


async def test_list_detections_accepts_dict_payload_through_runner():
    out = await Runner().execute(
        CrowdStrikeListDetectionsNode(),
        {"severity": "high", "limit": 10},
        _ctx(),
    )
    assert out.count >= 1
    assert all(d["max_severity"] >= 70 for d in out.detections)


def test_list_detections_node_is_registered():
    assert (
        NodeRegistry.get("integration.crowdstrike.list_detections") is CrowdStrikeListDetectionsNode
    )


async def test_list_detections_raises_in_non_mock_mode(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    with pytest.raises(NotImplementedError, match="Sprint 2"):
        await CrowdStrikeListDetectionsNode().run(
            CrowdStrikeListDetectionsInput(severity="all"),
            _ctx(),
        )


# ---------------------------------------------------------------------------
# isolate_host
# ---------------------------------------------------------------------------


async def test_isolate_host_returns_contained_for_known_host():
    out = await Runner().execute(
        CrowdStrikeIsolateHostNode(),
        CrowdStrikeIsolateHostInput(hostname="WS-JSMITH-PC"),
        _ctx(),
    )
    assert isinstance(out, CrowdStrikeIsolateHostOutput)
    assert out.contained is True
    assert out.status == "contained"
    assert out.device_id == "dev_01HXR4ABCDEF1234567890"


async def test_isolate_host_returns_not_found_for_unknown_host():
    """Unknown hosts yield the documented empty / not_found shape."""
    out = await Runner().execute(
        CrowdStrikeIsolateHostNode(),
        CrowdStrikeIsolateHostInput(hostname="DOES-NOT-EXIST"),
        _ctx(),
    )
    assert out.contained is False
    assert out.status == "not_found"
    assert out.device_id is None


async def test_isolate_host_accepts_dict_payload_through_runner():
    out = await Runner().execute(
        CrowdStrikeIsolateHostNode(),
        {"hostname": "WS-JSMITH-PC"},
        _ctx(),
    )
    assert out.contained is True


def test_isolate_host_node_is_registered():
    assert NodeRegistry.get("integration.crowdstrike.isolate_host") is CrowdStrikeIsolateHostNode


async def test_isolate_host_raises_in_non_mock_mode(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    with pytest.raises(NotImplementedError, match="Sprint 2"):
        await CrowdStrikeIsolateHostNode().run(
            CrowdStrikeIsolateHostInput(hostname="WS-JSMITH-PC"),
            _ctx(),
        )
