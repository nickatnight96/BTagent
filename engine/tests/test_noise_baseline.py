"""Tests for NoiseBaselineNode (#99 Phase B)."""

from __future__ import annotations

import pytest
from btagent_shared.types.hunt import Backend

from btagent_engine import NodeContext
from btagent_engine.data import (
    NoiseBaselineInput,
    NoiseBaselineNode,
    NoiseBaselineOutput,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_nb", org_id="org_test")


async def test_returns_profile_in_mock_mode(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    out = await NoiseBaselineNode().run(
        NoiseBaselineInput(ttp_id="T1059.001", backend=Backend.SPLUNK),
        _ctx(),
    )
    assert isinstance(out, NoiseBaselineOutput)
    assert out.mock_mode is True
    assert out.profile.expected_hits_per_day is not None
    assert out.profile.expected_hits_per_day >= 1
    assert out.profile.sample_window_days == 30
    assert out.profile.computed_at is not None


async def test_estimate_is_deterministic(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    a = await NoiseBaselineNode().run(
        NoiseBaselineInput(ttp_id="T1110", backend=Backend.SENTINEL), _ctx()
    )
    b = await NoiseBaselineNode().run(
        NoiseBaselineInput(ttp_id="T1110", backend=Backend.SENTINEL), _ctx()
    )
    assert a.profile.expected_hits_per_day == b.profile.expected_hits_per_day


async def test_different_backends_give_different_estimates(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    splunk = await NoiseBaselineNode().run(
        NoiseBaselineInput(ttp_id="T1059.001", backend=Backend.SPLUNK), _ctx()
    )
    elastic = await NoiseBaselineNode().run(
        NoiseBaselineInput(ttp_id="T1059.001", backend=Backend.ELASTIC), _ctx()
    )
    # Hash-seeded per (ttp, backend) — overwhelmingly likely to differ.
    assert splunk.profile.expected_hits_per_day != elastic.profile.expected_hits_per_day


async def test_custom_sample_window_respected(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    out = await NoiseBaselineNode().run(
        NoiseBaselineInput(ttp_id="T1486", backend=Backend.SPLUNK, sample_window_days=90),
        _ctx(),
    )
    assert out.profile.sample_window_days == 90


async def test_non_mock_mode_raises(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    with pytest.raises(NotImplementedError):
        await NoiseBaselineNode().run(
            NoiseBaselineInput(ttp_id="T1059.001", backend=Backend.SPLUNK),
            _ctx(),
        )
