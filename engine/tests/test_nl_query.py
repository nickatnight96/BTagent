"""Tests for NLQueryNode (UC-1.1, #104)."""

from __future__ import annotations

import pytest

from btagent_engine import NodeContext
from btagent_engine.reasoning import NLQueryInput, NLQueryNode, NLQueryOutput
from btagent_shared.types.hunt import Backend


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_nlq", org_id="org_test")


# --------------------------------------------------------------------------- #
# The canonical example from the NightWing catalog
# --------------------------------------------------------------------------- #


async def test_canonical_cobalt_strike_intent(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await NLQueryNode().run(
        NLQueryInput(
            intent="Show me all high-severity Cobalt Strike beaconing in the "
            "last 72 hours across finance enclave hosts",
            backends=[Backend.SPLUNK, Backend.SENTINEL],
        ),
        _ctx(),
    )
    assert isinstance(out, NLQueryOutput)
    assert out.mock_mode is True
    p = out.parsed
    assert p.time_window_hours == 72
    assert p.severity == "high"
    assert "cobalt strike" in p.keywords
    assert "beacon" in p.keywords
    # Cobalt Strike / beaconing -> C2 technique
    assert "T1071.001" in p.mitre_techniques
    # Splunk query carries the window + severity + a capped result
    spl = out.queries[Backend.SPLUNK].query
    assert "earliest=-72h" in spl
    assert "severity=high" in spl
    assert "head 1000" in spl


# --------------------------------------------------------------------------- #
# Time-window parsing
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "phrase,expected_hours",
    [
        ("in the last 24 hours", 24),
        ("past 7 days", 168),
        ("within 30 minutes", 1),  # 30 min rounds to <1h -> clamped to 1
        ("last 2 weeks", 336),
        ("previous 3 hours", 3),
    ],
)
async def test_time_window_parsing(monkeypatch, phrase, expected_hours):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await NLQueryNode().run(
        NLQueryInput(intent=f"show failed logins {phrase}", backends=[Backend.SPLUNK]),
        _ctx(),
    )
    assert out.parsed.time_window_hours == expected_hours


async def test_no_time_window_defaults_to_24h(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await NLQueryNode().run(
        NLQueryInput(intent="show me powershell activity", backends=[Backend.SPLUNK]),
        _ctx(),
    )
    assert out.parsed.time_window_hours == 24


# --------------------------------------------------------------------------- #
# Entity extraction
# --------------------------------------------------------------------------- #


async def test_ip_entity_extraction(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await NLQueryNode().run(
        NLQueryInput(
            intent="find all traffic to 185.220.101.42 in the last 24 hours",
            backends=[Backend.SPLUNK],
        ),
        _ctx(),
    )
    assert out.parsed.entities.get("ip") == ["185.220.101.42"]
    assert '185.220.101.42' in out.queries[Backend.SPLUNK].query


async def test_user_entity_extraction(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await NLQueryNode().run(
        NLQueryInput(
            intent="show logins for admin@corp.example.com today",
            backends=[Backend.SENTINEL],
        ),
        _ctx(),
    )
    assert "admin@corp.example.com" in out.parsed.entities.get("user", [])


# --------------------------------------------------------------------------- #
# MITRE detection
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "intent,expected_ttp",
    [
        ("hunt for powershell encoded commands", "T1059.001"),
        ("find brute force attempts", "T1110"),
        ("look for ransomware encryption", "T1486"),
        ("detect scheduled task persistence", "T1053.005"),
        ("spearphishing attachments this week", "T1566.001"),
    ],
)
async def test_mitre_detection(monkeypatch, intent, expected_ttp):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await NLQueryNode().run(
        NLQueryInput(intent=intent, backends=[Backend.SPLUNK]),
        _ctx(),
    )
    assert expected_ttp in out.parsed.mitre_techniques


# --------------------------------------------------------------------------- #
# Backend coverage + safety
# --------------------------------------------------------------------------- #


async def test_default_backends_when_unspecified(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await NLQueryNode().run(
        NLQueryInput(intent="show powershell in the last 24 hours"),
        _ctx(),
    )
    assert set(out.queries) == {
        Backend.SPLUNK,
        Backend.SENTINEL,
        Backend.ELASTIC,
        Backend.SIGMA,
    }


async def test_all_queries_are_count_capped(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await NLQueryNode().run(
        NLQueryInput(
            intent="show high severity beaconing last 24 hours",
            backends=[Backend.SPLUNK, Backend.SENTINEL, Backend.ELASTIC],
        ),
        _ctx(),
    )
    assert "head 1000" in out.queries[Backend.SPLUNK].query
    assert "take 1000" in out.queries[Backend.SENTINEL].query
    assert "head 1000" in out.queries[Backend.ELASTIC].query


async def test_sigma_query_tags_detected_technique(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await NLQueryNode().run(
        NLQueryInput(intent="hunt powershell beaconing", backends=[Backend.SIGMA]),
        _ctx(),
    )
    sigma = out.queries[Backend.SIGMA].query
    assert "attack.t1059_001" in sigma or "attack.t1071_001" in sigma


# --------------------------------------------------------------------------- #
# Mock-mode toggle
# --------------------------------------------------------------------------- #


async def test_non_mock_mode_degrades_gracefully(monkeypatch):
    # No LLM path yet -> must NOT raise under MOCK_LLM=false; deterministic
    # regex/keyword parser is used so composing pipelines don't break.
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    out = await NLQueryNode().run(
        NLQueryInput(intent="show me powershell", backends=[Backend.SPLUNK]),
        _ctx(),
    )
    assert Backend.SPLUNK in out.queries


async def test_llm_parse_used_when_client_registered(monkeypatch):
    from btagent_engine.llm import clear_llm_client, set_llm_client
    from btagent_shared.llm import LLMRequest, LLMResponse

    class _FakeClient:
        async def complete(self, request: LLMRequest) -> LLMResponse:
            return LLMResponse(
                content='{"time_window_hours":48,"severity":"high",'
                '"entities":{"ip":["9.9.9.9"]},"keywords":["beacon"],'
                '"mitre_techniques":["T1071.001"]}',
                provider="anthropic", model="claude-haiku-4-5-20251001",
            )

    clear_llm_client(); set_llm_client(_FakeClient())
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    try:
        out = await NLQueryNode().run(
            NLQueryInput(intent="anything", backends=[Backend.SPLUNK]), _ctx()
        )
        assert out.mock_mode is False
        assert out.parsed.time_window_hours == 48
        assert out.parsed.severity == "high"
        assert "9.9.9.9" in out.parsed.entities.get("ip", [])
        # query built deterministically from the LLM-parsed structure
        assert "earliest=-48h" in out.queries[Backend.SPLUNK].query
    finally:
        clear_llm_client()
