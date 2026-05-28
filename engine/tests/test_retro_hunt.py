"""Tests for RetroHuntNode (UC-4.3, #107) — closes EPIC-4."""

from __future__ import annotations

import pytest
from btagent_shared.types.config import AutonomyLevel
from btagent_shared.types.hunt import HuntInput, HuntScope
from btagent_shared.types.investigation import IOC

from btagent_engine import NodeContext
from btagent_engine.reasoning import (
    RetroHuntInput,
    RetroHuntNode,
    RetroHuntOutput,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_retro", org_id="org_test")


def _ioc(value: str, type_: str = "ip") -> IOC:
    return IOC(
        id=f"ioc_{value}",
        investigation_id="inv_test",
        type=type_,
        value=value,
        confidence=0.9,
        source="advisory",
        tlp="amber",
    )


def _hunt_input(iocs) -> HuntInput:
    return HuntInput(
        iocs=iocs,
        initiated_by="usr_test",
        autonomy_level=AutonomyLevel.L2_SUPERVISED,
        scope=HuntScope(),
    )


# --------------------------------------------------------------------------- #
# Sighting found -> compromise suspected
# --------------------------------------------------------------------------- #


async def test_known_ioc_registers_sighting(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    # 10.1.42.17 is in the correlation fixtures across 4 connectors.
    out = await RetroHuntNode().run(
        RetroHuntInput(hunt_input=_hunt_input([_ioc("10.1.42.17")])),
        _ctx(),
    )
    assert isinstance(out, RetroHuntOutput)
    r = out.report
    assert r.compromise_suspected is True
    assert r.iocs_checked == 1
    assert len(r.sightings) == 1
    s = r.sightings[0]
    assert s.ioc_value == "10.1.42.17"
    assert s.event_count >= 3  # multiple connectors had events
    assert s.first_seen is not None and s.last_seen is not None
    assert s.first_seen <= s.last_seen


async def test_sightings_grouped_by_tactic(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await RetroHuntNode().run(
        RetroHuntInput(hunt_input=_hunt_input([_ioc("10.1.42.17")])),
        _ctx(),
    )
    # IP -> T1071.001 (HypothesisGen default) -> command-and-control tactic
    assert "command-and-control" in out.report.sightings_by_tactic


# --------------------------------------------------------------------------- #
# No sighting -> clean
# --------------------------------------------------------------------------- #


async def test_unknown_ioc_no_sighting(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await RetroHuntNode().run(
        RetroHuntInput(hunt_input=_hunt_input([_ioc("203.0.113.255")])),
        _ctx(),
    )
    assert out.report.compromise_suspected is False
    assert out.report.sightings == []
    assert out.report.coverage_gaps == []


# --------------------------------------------------------------------------- #
# Coverage-gap flagging
# --------------------------------------------------------------------------- #


async def test_seen_technique_without_detection_is_a_gap(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await RetroHuntNode().run(
        RetroHuntInput(
            hunt_input=_hunt_input([_ioc("10.1.42.17")]),
            covered_technique_ids=[],  # nothing covered
        ),
        _ctx(),
    )
    assert out.report.coverage_gaps  # the seen technique is an uncovered gap


async def test_seen_technique_with_detection_no_gap(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    # Pre-seed coverage with the technique the IP maps to (T1071.001).
    out = await RetroHuntNode().run(
        RetroHuntInput(
            hunt_input=_hunt_input([_ioc("10.1.42.17")]),
            covered_technique_ids=["T1071.001"],
        ),
        _ctx(),
    )
    assert "T1071.001" not in out.report.coverage_gaps


# --------------------------------------------------------------------------- #
# Window + mock toggle
# --------------------------------------------------------------------------- #


async def test_window_days_propagates(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await RetroHuntNode().run(
        RetroHuntInput(hunt_input=_hunt_input([_ioc("10.1.42.17")]), window_days=180),
        _ctx(),
    )
    assert out.report.window_days == 180


async def test_non_mock_mode_raises(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    with pytest.raises(NotImplementedError):
        await RetroHuntNode().run(
            RetroHuntInput(hunt_input=_hunt_input([_ioc("10.1.42.17")])),
            _ctx(),
        )
