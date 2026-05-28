"""Tests for PatternClusterNode (UC-4.2, #107)."""

from __future__ import annotations

from datetime import UTC, datetime, timezone

import pytest
from btagent_shared.types.connector import OCSFEventClass
from btagent_shared.types.correlation import MitreTag, NormalizedEvent, RawEventRef

from btagent_engine import NodeContext
from btagent_engine.reasoning import (
    PatternClusterInput,
    PatternClusterNode,
    PatternClusterOutput,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_pc", org_id="org_test")


def _ev(eid: str, host: str, ttp: str, conf: float, **kw) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=eid,
        timestamp=datetime.now(UTC),
        source_connector="crowdstrike",
        ocsf_event_class=OCSFEventClass.PROCESS_ACTIVITY,
        host=host,
        raw_ref=RawEventRef(
            connector="crowdstrike", capability_id="x", queried_at=datetime.now(UTC)
        ),
        mitre_techniques=[MitreTag(technique_id=ttp, name="PowerShell", confidence=conf)],
        **kw,
    )


async def test_clusters_by_technique_and_host(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    events = [
        _ev("1", "HOST-A", "T1059.001", 0.9),
        _ev("2", "HOST-A", "T1059.001", 0.8),  # same technique+host -> same cluster
        _ev("3", "HOST-B", "T1059.001", 0.7),  # same technique, diff host -> diff cluster
    ]
    out = await PatternClusterNode().run(
        PatternClusterInput(events=events, min_confidence=0.5), _ctx()
    )
    assert isinstance(out, PatternClusterOutput)
    assert len(out.clusters) == 2  # (T1059.001, HOST-A) and (T1059.001, HOST-B)
    host_a = next(c for c in out.clusters if "HOST-A" in c.id or "HOST_A" in c.id)
    assert set(host_a.event_ids) == {"1", "2"}
    assert host_a.confidence == 0.9  # max in cluster


async def test_below_threshold_events_dropped(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    events = [_ev("1", "HOST-A", "T1059.001", 0.3)]
    out = await PatternClusterNode().run(
        PatternClusterInput(events=events, min_confidence=0.5), _ctx()
    )
    assert out.clusters == []


async def test_affected_entities_rolled_up(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    events = [
        _ev("1", "HOST-A", "T1110", 0.8, user="alice", source_ip="10.0.0.1"),
        _ev("2", "HOST-A", "T1110", 0.8, user="bob", source_ip="10.0.0.1"),
    ]
    out = await PatternClusterNode().run(PatternClusterInput(events=events), _ctx())
    cluster = out.clusters[0]
    assert set(cluster.affected_entities["user"]) == {"alice", "bob"}
    assert cluster.affected_entities["source_ip"] == ["10.0.0.1"]


async def test_empty_events(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await PatternClusterNode().run(PatternClusterInput(events=[]), _ctx())
    assert out.clusters == []


async def test_non_mock_mode_degrades_gracefully(monkeypatch):
    # No LLM path yet -> must NOT raise under MOCK_LLM=false; deterministic
    # group-by is used so composing pipelines don't break.
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    out = await PatternClusterNode().run(PatternClusterInput(events=[]), _ctx())
    assert out.clusters == []
