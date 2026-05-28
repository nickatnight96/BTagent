"""Tests for PivotSuggestNode (UC-1.2, #104)."""

from __future__ import annotations

from datetime import UTC, datetime, timezone

import pytest
from btagent_shared.types.connector import OCSFEventClass
from btagent_shared.types.correlation import NormalizedEvent, RawEventRef
from btagent_shared.types.enums import IOCType

from btagent_engine import NodeContext
from btagent_engine.reasoning import (
    PivotSuggestInput,
    PivotSuggestNode,
    PivotSuggestOutput,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_pivot", org_id="org_test")


def _event(**kw) -> NormalizedEvent:
    base = dict(
        event_id=kw.pop("event_id", "e1"),
        timestamp=datetime.now(UTC),
        source_connector="splunk",
        ocsf_event_class=OCSFEventClass.NETWORK_ACTIVITY,
        raw_ref=RawEventRef(connector="splunk", capability_id="x", queried_at=datetime.now(UTC)),
    )
    base.update(kw)
    return NormalizedEvent(**base)


async def test_ranks_cooccurring_entities(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    events = [
        _event(event_id="1", source_ip="10.0.0.1", dest_ip="9.9.9.9"),
        _event(event_id="2", source_ip="10.0.0.1", dest_ip="9.9.9.9"),
        _event(event_id="3", source_ip="10.0.0.1", host="HOST-A"),
    ]
    out = await PivotSuggestNode().run(
        PivotSuggestInput(entity_value="10.0.0.1", events=events), _ctx()
    )
    assert isinstance(out, PivotSuggestOutput)
    assert 3 <= len(out.pivots) <= 5
    # The most-frequent co-occurring entity (9.9.9.9, 2x) should rank first.
    assert out.pivots[0].entity_value == "9.9.9.9"


async def test_never_suggests_queried_entity_as_concrete_pivot(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    # An event where dest_ip == the queried entity. The co-occurrence
    # extractor must NOT propose pivoting to the entity we already
    # searched. (Generic scope-widening pivots of type OTHER may still
    # reference the entity — those are "widen the window for X" hints.)
    events = [
        _event(source_ip="8.8.8.8", dest_ip="10.0.0.1"),
        _event(event_id="2", source_ip="9.9.9.9", dest_ip="10.0.0.1"),
    ]
    out = await PivotSuggestNode().run(
        PivotSuggestInput(entity_value="10.0.0.1", events=events), _ctx()
    )
    concrete = [p for p in out.pivots if p.entity_type == IOCType.IP]
    assert all(p.entity_value != "10.0.0.1" for p in concrete)
    # It should instead surface the *other* IPs as pivots.
    assert any(p.entity_value in {"8.8.8.8", "9.9.9.9"} for p in concrete)


async def test_sparse_timeline_tops_up_to_min_pivots(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await PivotSuggestNode().run(
        PivotSuggestInput(entity_value="10.0.0.1", events=[]), _ctx()
    )
    # No co-occurring entities -> generic pivots fill to the minimum.
    assert len(out.pivots) >= 3


async def test_deterministic_ordering(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    events = [
        _event(event_id="1", source_ip="10.0.0.1", dest_ip="9.9.9.9"),
        _event(event_id="2", source_ip="10.0.0.1", host="HOST-A"),
    ]
    a = await PivotSuggestNode().run(
        PivotSuggestInput(entity_value="10.0.0.1", events=events), _ctx()
    )
    b = await PivotSuggestNode().run(
        PivotSuggestInput(entity_value="10.0.0.1", events=events), _ctx()
    )
    assert [p.entity_value for p in a.pivots] == [p.entity_value for p in b.pivots]


async def test_non_mock_mode_degrades_gracefully(monkeypatch):
    # No LLM path yet -> must NOT raise under MOCK_LLM=false; deterministic
    # frequency-rank strategy is used so composing pipelines don't break.
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    out = await PivotSuggestNode().run(
        PivotSuggestInput(entity_value="10.0.0.1", events=[]), _ctx()
    )
    assert len(out.pivots) >= 3
