"""UC-1.2 acceptance tests — CorrelationWorkbenchNode (#104).

Exercises the full entity -> fan-out -> normalize -> tag -> pivot chain
against the deterministic fixture set, asserting each catalog
acceptance criterion.
"""

from __future__ import annotations

import pytest

from btagent_engine import NodeContext
from btagent_engine.reasoning.correlation_workbench import (
    AUDIT_METADATA_KEY,
    CorrelationWorkbenchInput,
    CorrelationWorkbenchNode,
)
from btagent_shared.types.enums import IOCType


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_uc12", org_id="org_test")


# --------------------------------------------------------------------------- #
# ≥3 sources correlated into one timeline
# --------------------------------------------------------------------------- #


async def test_ip_correlates_at_least_three_sources(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    out = await CorrelationWorkbenchNode().run(
        CorrelationWorkbenchInput(entity_type=IOCType.IP, entity_value="10.1.42.17"),
        _ctx(),
    )
    tl = out.timeline
    assert len(tl.sources_queried) >= 3
    assert len(tl.events) >= 3
    assert tl.mock_mode is True


# --------------------------------------------------------------------------- #
# Field normalization — src_ip (Splunk) and source.ip (Elastic) both ->
# canonical source_ip
# --------------------------------------------------------------------------- #


async def test_field_names_normalized_across_vendors(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    out = await CorrelationWorkbenchNode().run(
        CorrelationWorkbenchInput(entity_type=IOCType.IP, entity_value="10.1.42.17"),
        _ctx(),
    )
    # Both the Splunk events (src_ip) and the Elastic event (source.ip)
    # must surface the same canonical source_ip value.
    splunk_evs = [e for e in out.timeline.events if e.source_connector == "splunk"]
    elastic_evs = [e for e in out.timeline.events if e.source_connector == "elastic"]
    assert splunk_evs and elastic_evs
    assert all(e.source_ip == "10.1.42.17" for e in splunk_evs)
    assert all(e.source_ip == "10.1.42.17" for e in elastic_evs)


# --------------------------------------------------------------------------- #
# Timeline sorted ascending by UTC timestamp
# --------------------------------------------------------------------------- #


async def test_timeline_sorted_by_utc_timestamp(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    out = await CorrelationWorkbenchNode().run(
        CorrelationWorkbenchInput(entity_type=IOCType.IP, entity_value="10.1.42.17"),
        _ctx(),
    )
    ts = [e.timestamp for e in out.timeline.events]
    assert ts == sorted(ts)
    # All timestamps tz-aware UTC (the normalization payoff)
    assert all(e.timestamp.tzinfo is not None for e in out.timeline.events)


# --------------------------------------------------------------------------- #
# MITRE auto-tagging, threshold-sensitive
# --------------------------------------------------------------------------- #


async def test_mitre_tagging_present_and_threshold_sensitive(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")  # pivot node uses this gate

    low = await CorrelationWorkbenchNode().run(
        CorrelationWorkbenchInput(
            entity_type=IOCType.IP,
            entity_value="10.1.42.17",
            mitre_confidence_threshold=0.1,
        ),
        _ctx(),
    )
    high = await CorrelationWorkbenchNode().run(
        CorrelationWorkbenchInput(
            entity_type=IOCType.IP,
            entity_value="10.1.42.17",
            mitre_confidence_threshold=0.99,
        ),
        _ctx(),
    )
    low_tags = sum(len(e.mitre_techniques) for e in low.timeline.events)
    high_tags = sum(len(e.mitre_techniques) for e in high.timeline.events)
    # The CrowdStrike event has a powershell command line -> T1059.001.
    assert low_tags >= 1
    # Raising the threshold cannot increase the number of tags.
    assert high_tags <= low_tags


# --------------------------------------------------------------------------- #
# 3–5 pivots with rationale
# --------------------------------------------------------------------------- #


async def test_pivots_returned_with_rationale(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await CorrelationWorkbenchNode().run(
        CorrelationWorkbenchInput(entity_type=IOCType.IP, entity_value="10.1.42.17"),
        _ctx(),
    )
    assert 3 <= len(out.timeline.pivots) <= 5
    for p in out.timeline.pivots:
        assert p.rationale.strip()
    # Should never suggest pivoting back to the queried entity itself.
    assert all(p.entity_value != "10.1.42.17" for p in out.timeline.pivots
               if p.entity_type == IOCType.IP)


# --------------------------------------------------------------------------- #
# Audit trail + lineage
# --------------------------------------------------------------------------- #


async def test_audit_trail_one_entry_per_source(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    out = await CorrelationWorkbenchNode().run(
        CorrelationWorkbenchInput(entity_type=IOCType.IP, entity_value="10.1.42.17"),
        _ctx(),
    )
    tl = out.timeline
    # One audit entry per source queried.
    assert len(tl.audit_trail) == len(tl.sources_queried)
    for entry in tl.audit_trail:
        assert entry.connector
        assert entry.queried_at is not None
        assert entry.query


async def test_lineage_every_event_has_raw_ref_and_raw_event(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    out = await CorrelationWorkbenchNode().run(
        CorrelationWorkbenchInput(entity_type=IOCType.IP, entity_value="10.1.42.17"),
        _ctx(),
    )
    for e in out.timeline.events:
        assert e.raw_ref.connector == e.source_connector
        assert e.raw_event  # non-empty verbatim vendor event
        assert e.event_id


async def test_audit_written_to_ctx_metadata(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    ctx = _ctx()
    await CorrelationWorkbenchNode().run(
        CorrelationWorkbenchInput(entity_type=IOCType.IP, entity_value="10.1.42.17"),
        ctx,
    )
    assert AUDIT_METADATA_KEY in ctx.metadata
    assert isinstance(ctx.metadata[AUDIT_METADATA_KEY], list)


# --------------------------------------------------------------------------- #
# User-entity correlation (identity + SIEM)
# --------------------------------------------------------------------------- #


async def test_user_entity_correlates_identity_and_siem(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    out = await CorrelationWorkbenchNode().run(
        CorrelationWorkbenchInput(entity_type=IOCType.OTHER, entity_value="jsmith"),
        _ctx(),
    )
    sources = set(out.timeline.sources_queried)
    assert "sentinel" in sources
    assert "splunk" in sources
    # The failed-login Sentinel event should surface canonical user field.
    assert any(e.user and "jsmith" in e.user for e in out.timeline.events)


# --------------------------------------------------------------------------- #
# Unknown entity -> empty timeline but real audit
# --------------------------------------------------------------------------- #


async def test_unknown_entity_yields_empty_timeline_with_audit(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    out = await CorrelationWorkbenchNode().run(
        CorrelationWorkbenchInput(entity_type=IOCType.IP, entity_value="203.0.113.255"),
        _ctx(),
    )
    assert out.timeline.events == []
    # We still queried the fallback connectors -> audit trail is non-empty.
    assert len(out.timeline.audit_trail) >= 1


# --------------------------------------------------------------------------- #
# Mock-mode toggle
# --------------------------------------------------------------------------- #


async def test_non_mock_mode_raises(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    with pytest.raises(NotImplementedError):
        await CorrelationWorkbenchNode().run(
            CorrelationWorkbenchInput(entity_type=IOCType.IP, entity_value="10.1.42.17"),
            _ctx(),
        )
