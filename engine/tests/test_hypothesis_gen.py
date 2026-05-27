"""Tests for the HypothesisGenNode (#99 Phase A).

Covers the mock-mode deterministic path: adversary stock-sets,
explicit-TTP passthrough, IOC-derived defaults, dedup-on-ttp-id, and
the priority ordering invariant. The non-mock LLM path raises
NotImplementedError today, which we also assert.
"""

from __future__ import annotations

import pytest

from btagent_engine import NodeContext
from btagent_engine.reasoning import (
    HypothesisGenInput,
    HypothesisGenNode,
    HypothesisGenOutput,
)
from btagent_shared.types.config import AutonomyLevel
from btagent_shared.types.hunt import HuntInput, HuntScope
from btagent_shared.types.investigation import IOC


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_hyp", org_id="org_test")


def _hi(**overrides) -> HuntInput:
    base = {
        "initiated_by": "usr_test",
        "autonomy_level": AutonomyLevel.L2_SUPERVISED,
        "scope": HuntScope(),
    }
    base.update(overrides)
    return HuntInput(**base)


# --------------------------------------------------------------------------- #
# Adversary expansion
# --------------------------------------------------------------------------- #


async def test_named_adversary_expands_to_stock_ttps(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await HypothesisGenNode().run(
        HypothesisGenInput(hunt_input=_hi(adversaries=["APT29"])),
        _ctx(),
    )
    assert isinstance(out, HypothesisGenOutput)
    assert out.mock_mode is True
    ttps = {h.ttp_id for h in out.hypotheses}
    # APT29 stock set per _ADVERSARY_STOCK_TTPS
    assert {"T1059.001", "T1078.004", "T1566.001"}.issubset(ttps)
    # Adversary-derived hypotheses get the highest priority
    for h in out.hypotheses:
        assert h.priority >= 0.85 - 0.01
        assert "adversary:APT29" in h.sources


async def test_unknown_adversary_emits_placeholder_hypothesis(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await HypothesisGenNode().run(
        HypothesisGenInput(hunt_input=_hi(adversaries=["UnknownGang"])),
        _ctx(),
    )
    assert len(out.hypotheses) == 1
    h = out.hypotheses[0]
    assert h.ttp_id == "T0000"
    assert "UnknownGang" in h.rationale


# --------------------------------------------------------------------------- #
# Explicit TTPs
# --------------------------------------------------------------------------- #


async def test_explicit_ttp_passthrough(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await HypothesisGenNode().run(
        HypothesisGenInput(hunt_input=_hi(ttps=["T1110", "T1003.001"])),
        _ctx(),
    )
    ttps = {h.ttp_id for h in out.hypotheses}
    assert ttps == {"T1110", "T1003.001"}
    for h in out.hypotheses:
        assert "analyst:explicit" in h.sources


# --------------------------------------------------------------------------- #
# IOC-derived
# --------------------------------------------------------------------------- #


async def test_ioc_maps_to_default_ttp(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    ioc = IOC(
        id="ioc_x",
        investigation_id="inv_test",
        type="ip",
        value="8.8.8.8",
        confidence=0.9,
        source="test",
        tlp="green",
    )
    out = await HypothesisGenNode().run(
        HypothesisGenInput(hunt_input=_hi(iocs=[ioc])),
        _ctx(),
    )
    assert len(out.hypotheses) == 1
    h = out.hypotheses[0]
    assert h.ttp_id == "T1071.001"  # IP -> Web Protocols heuristic
    assert "ioc:ip:8.8.8.8" in h.sources


async def test_ioc_with_unmapped_type_is_skipped(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    ioc = IOC(
        id="ioc_x",
        investigation_id="inv_test",
        type="other",
        value="foo",
        confidence=0.5,
        source="test",
        tlp="green",
    )
    out = await HypothesisGenNode().run(
        HypothesisGenInput(hunt_input=_hi(iocs=[ioc])),
        _ctx(),
    )
    assert out.hypotheses == []


# --------------------------------------------------------------------------- #
# Dedup + ordering
# --------------------------------------------------------------------------- #


async def test_dedup_keeps_highest_priority_entry(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    # APT29 stock-set includes T1059.001; the explicit-TTP path also
    # emits T1059.001 (lower priority). Dedup should keep the adversary
    # entry (priority 0.85) and merge sources.
    out = await HypothesisGenNode().run(
        HypothesisGenInput(
            hunt_input=_hi(adversaries=["APT29"], ttps=["T1059.001"])
        ),
        _ctx(),
    )
    powershell = next(h for h in out.hypotheses if h.ttp_id == "T1059.001")
    assert powershell.priority == 0.85
    # Both provenance trails should be present after the merge.
    assert "adversary:APT29" in powershell.sources
    assert "analyst:explicit" in powershell.sources


async def test_priority_ordering_invariant(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    ioc = IOC(
        id="ioc_x",
        investigation_id="inv_test",
        type="ip",
        value="1.2.3.4",
        confidence=0.5,
        source="t",
        tlp="green",
    )
    out = await HypothesisGenNode().run(
        HypothesisGenInput(
            hunt_input=_hi(
                adversaries=["APT29"],
                ttps=["T1110"],
                iocs=[ioc],
            )
        ),
        _ctx(),
    )
    priorities = [h.priority for h in out.hypotheses]
    assert priorities == sorted(priorities, reverse=True)


# --------------------------------------------------------------------------- #
# Mock-mode toggle
# --------------------------------------------------------------------------- #


async def test_non_mock_no_client_degrades_to_deterministic(monkeypatch):
    # MOCK_LLM=false but no client registered -> deterministic fallback,
    # never raises (so pipelines composing this node don't break).
    from btagent_engine.llm import clear_llm_client

    clear_llm_client()
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    out = await HypothesisGenNode().run(
        HypothesisGenInput(hunt_input=_hi(adversaries=["APT29"])),
        _ctx(),
    )
    assert out.mock_mode is True
    assert {h.ttp_id for h in out.hypotheses} >= {"T1059.001", "T1078.004"}


async def test_non_mock_with_client_uses_llm(monkeypatch):
    """A registered client + MOCK_LLM=false -> the node uses the LLM path."""
    from btagent_engine.llm import clear_llm_client, set_llm_client
    from btagent_shared.llm import LLMRequest, LLMResponse, LLMUsage

    class _FakeClient:
        async def complete(self, request: LLMRequest) -> LLMResponse:
            return LLMResponse(
                content='[{"ttp_id":"T1566.001","ttp_name":"Spearphishing",'
                '"rationale":"actor phishes","behavioral_description":"watch attachments",'
                '"priority":0.9}]',
                provider="anthropic",
                model="claude-sonnet-4-6",
                usage=LLMUsage(input_tokens=30, output_tokens=20),
            )

    clear_llm_client()
    set_llm_client(_FakeClient())
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    try:
        out = await HypothesisGenNode().run(
            HypothesisGenInput(hunt_input=_hi(adversaries=["APT29"])),
            _ctx(),
        )
        assert out.mock_mode is False
        assert out.hypotheses[0].ttp_id == "T1566.001"
        assert out.hypotheses[0].sources == ["llm"]
    finally:
        clear_llm_client()


async def test_llm_failure_falls_back_to_deterministic(monkeypatch):
    """A malformed LLM response must degrade to deterministic, not crash."""
    from btagent_engine.llm import clear_llm_client, set_llm_client
    from btagent_shared.llm import LLMRequest, LLMResponse

    class _BadClient:
        async def complete(self, request: LLMRequest) -> LLMResponse:
            return LLMResponse(content="not json at all", provider="x", model="y")

    clear_llm_client()
    set_llm_client(_BadClient())
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    try:
        out = await HypothesisGenNode().run(
            HypothesisGenInput(hunt_input=_hi(adversaries=["APT29"])),
            _ctx(),
        )
        # fell back to deterministic
        assert out.mock_mode is True
        assert out.hypotheses
    finally:
        clear_llm_client()
