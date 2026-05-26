"""Tests for QuerySynthNode (#99 Phase B)."""

from __future__ import annotations

import pytest

from btagent_engine import NodeContext
from btagent_engine.reasoning import (
    QuerySynthInput,
    QuerySynthNode,
    QuerySynthOutput,
)
from btagent_shared.types.hunt import Backend


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_qs", org_id="org_test")


async def test_known_ttp_emits_library_queries(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await QuerySynthNode().run(
        QuerySynthInput(ttp_id="T1059.001", backends=[Backend.SPLUNK, Backend.SENTINEL]),
        _ctx(),
    )
    assert isinstance(out, QuerySynthOutput)
    assert out.mock_mode is True
    assert set(out.queries) == {Backend.SPLUNK, Backend.SENTINEL}
    # SPL template targets powershell + encoded command
    assert "powershell" in out.queries[Backend.SPLUNK].query.lower()
    assert "encodedcommand" in out.queries[Backend.SPLUNK].query.lower()


async def test_queries_are_count_capped(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await QuerySynthNode().run(
        QuerySynthInput(ttp_id="T1110", backends=[Backend.SPLUNK, Backend.SENTINEL]),
        _ctx(),
    )
    # Splunk -> | head, Sentinel -> take  (both cap result volume)
    assert "head" in out.queries[Backend.SPLUNK].query
    assert "take" in out.queries[Backend.SENTINEL].query


async def test_empty_backends_emits_all_default_backends(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await QuerySynthNode().run(
        QuerySynthInput(ttp_id="T1059.001"),  # no backends -> all
        _ctx(),
    )
    # T1059.001 library entry covers all 5 default backends
    assert set(out.queries) == {
        Backend.SPLUNK,
        Backend.SENTINEL,
        Backend.ELASTIC,
        Backend.CROWDSTRIKE,
        Backend.SIGMA,
    }


async def test_unknown_ttp_emits_generic_placeholder(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await QuerySynthNode().run(
        QuerySynthInput(ttp_id="T9999.999", backends=[Backend.SPLUNK]),
        _ctx(),
    )
    q = out.queries[Backend.SPLUNK]
    assert "TODO" in q.query
    assert "T9999.999" in q.query
    assert "refine" in q.notes.lower()


async def test_missing_library_backend_falls_back_to_generic(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    # T1566.001 library has no CrowdStrike entry -> generic fallback
    out = await QuerySynthNode().run(
        QuerySynthInput(ttp_id="T1566.001", backends=[Backend.CROWDSTRIKE]),
        _ctx(),
    )
    assert "TODO" in out.queries[Backend.CROWDSTRIKE].query


async def test_non_mock_mode_raises(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    with pytest.raises(NotImplementedError):
        await QuerySynthNode().run(
            QuerySynthInput(ttp_id="T1059.001", backends=[Backend.SPLUNK]),
            _ctx(),
        )
