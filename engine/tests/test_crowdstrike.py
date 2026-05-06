"""End-to-end tests for the CrowdStrike Nodes (list_detections + isolate_host)."""

from __future__ import annotations

import pytest

from btagent_engine import NodeContext, NodeRegistry, Runner
from btagent_engine.integrations.crowdstrike import (
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
