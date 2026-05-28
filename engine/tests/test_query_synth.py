"""Tests for QuerySynthNode (#99 Phase B)."""

from __future__ import annotations

import pytest
from btagent_shared.types.hunt import Backend

from btagent_engine import NodeContext
from btagent_engine.reasoning import (
    QuerySynthInput,
    QuerySynthNode,
    QuerySynthOutput,
)


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


async def test_non_mock_mode_degrades_gracefully(monkeypatch):
    # No LLM path yet -> must NOT raise under MOCK_LLM=false; it falls back
    # to the deterministic template library so composing pipelines don't break.
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    out = await QuerySynthNode().run(
        QuerySynthInput(ttp_id="T1059.001", backends=[Backend.SPLUNK]),
        _ctx(),
    )
    assert Backend.SPLUNK in out.queries


# --------------------------------------------------------------------------- #
# LLM path (a) — real client used; (b) bad response falls back
# --------------------------------------------------------------------------- #


async def test_llm_path_used_when_client_registered(monkeypatch):
    from btagent_shared.llm import LLMRequest, LLMResponse

    from btagent_engine.llm import clear_llm_client, set_llm_client

    class _FakeClient:
        async def complete(self, request: LLMRequest) -> LLMResponse:
            return LLMResponse(
                content='{"splunk":"index=ep process=powershell.exe | head 100"}',
                provider="anthropic",
                model="claude-sonnet-4-6",
            )

    clear_llm_client()
    set_llm_client(_FakeClient())
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    try:
        out = await QuerySynthNode().run(
            QuerySynthInput(ttp_id="T1059.001", backends=[Backend.SPLUNK]), _ctx()
        )
        assert out.mock_mode is False
        assert "head 100" in out.queries[Backend.SPLUNK].query
    finally:
        clear_llm_client()


async def test_llm_bad_response_falls_back_to_template(monkeypatch):
    from btagent_shared.llm import LLMRequest, LLMResponse

    from btagent_engine.llm import clear_llm_client, set_llm_client

    class _BadClient:
        async def complete(self, request: LLMRequest) -> LLMResponse:
            return LLMResponse(content="sorry, no", provider="x", model="y")

    clear_llm_client()
    set_llm_client(_BadClient())
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    try:
        out = await QuerySynthNode().run(
            QuerySynthInput(ttp_id="T1059.001", backends=[Backend.SPLUNK]), _ctx()
        )
        assert out.mock_mode is True  # fell back to template library
        assert Backend.SPLUNK in out.queries
    finally:
        clear_llm_client()
