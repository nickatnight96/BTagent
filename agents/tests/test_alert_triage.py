"""Tests for AlertTriageNode (EPIC-3 UC-3.1)."""

from __future__ import annotations

import pytest
from btagent_engine.node import NodeContext
from btagent_engine.reasoning import AlertTriageInput, AlertTriageNode, AlertTriageOutput
from btagent_shared.types.enums import Severity
from btagent_shared.types.triage import Alert, TriageDisposition, TypedIntent


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_triage", org_id="org_test")


def _alert(
    title: str, *, severity: Severity = Severity.MEDIUM, description: str = "", **entities
) -> Alert:
    return Alert(
        id="alrt_1",
        source="splunk",
        title=title,
        description=description,
        severity=severity,
        entities={k: list(v) for k, v in entities.items()},
    )


async def _triage(alert: Alert, monkeypatch) -> AlertTriageOutput:
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await AlertTriageNode().run(AlertTriageInput(alert=alert), _ctx())
    assert isinstance(out, AlertTriageOutput)
    assert out.mock_mode is True
    return out


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "title,expected_intent",
    [
        ("Ransomware payload quarantined on host WS-12", TypedIntent.MALWARE_DETECTED),
        ("Possible data exfiltration: large outbound transfer", TypedIntent.DATA_EXFIL_SUSPECTED),
        ("Cobalt Strike beaconing detected", TypedIntent.C2_BEACONING),
        ("Privilege escalation via UAC bypass", TypedIntent.PRIVILEGE_ESCALATION),
        ("Lateral movement via PsExec observed", TypedIntent.LATERAL_MOVEMENT),
        ("Spearphishing email with malicious attachment", TypedIntent.PHISHING),
        ("Port scan from internal host", TypedIntent.RECONNAISSANCE),
        ("Impossible travel sign-in for user", TypedIntent.SUSPICIOUS_LOGIN),
        ("Unauthorized software install — policy violation", TypedIntent.POLICY_VIOLATION),
        ("Known-good approved change window", TypedIntent.BENIGN),
        ("Widget rendered slowly on dashboard", TypedIntent.UNKNOWN),
    ],
)
async def test_intent_classification(monkeypatch, title, expected_intent):
    out = await _triage(_alert(title), monkeypatch)
    assert out.result.typed_intent == expected_intent


# --------------------------------------------------------------------------- #
# Severity redetermination (UC-3.1 AC)
# --------------------------------------------------------------------------- #


async def test_malware_escalates_to_critical(monkeypatch):
    out = await _triage(_alert("Ransomware detected", severity=Severity.LOW), monkeypatch)
    assert out.result.proposed_severity == Severity.CRITICAL
    assert out.result.severity_escalated is True
    assert out.result.disposition == TriageDisposition.ESCALATE


async def test_impossible_travel_login_escalates_to_high(monkeypatch):
    out = await _triage(
        _alert(
            "Anomalous sign-in", description="impossible travel detected", severity=Severity.LOW
        ),
        monkeypatch,
    )
    assert out.result.typed_intent == TypedIntent.SUSPICIOUS_LOGIN
    assert out.result.proposed_severity == Severity.HIGH
    assert out.result.severity_escalated is True
    assert out.result.disposition == TriageDisposition.ESCALATE


async def test_high_source_severity_not_downgraded(monkeypatch):
    # A plain suspicious login with no escalator keeps its source severity.
    out = await _triage(_alert("Failed login burst", severity=Severity.MEDIUM), monkeypatch)
    assert out.result.proposed_severity == Severity.MEDIUM
    assert out.result.severity_escalated is False
    assert out.result.disposition == TriageDisposition.INVESTIGATE


# --------------------------------------------------------------------------- #
# Disposition + structure
# --------------------------------------------------------------------------- #


async def test_benign_closes(monkeypatch):
    out = await _triage(_alert("Known-good maintenance task"), monkeypatch)
    assert out.result.disposition == TriageDisposition.CLOSE_BENIGN


async def test_result_has_next_steps_evidence_and_confidence(monkeypatch):
    out = await _triage(_alert("Cobalt Strike beaconing", ip=["10.1.1.5"]), monkeypatch)
    r = out.result
    assert 2 <= len(r.next_steps) <= 3
    assert all(s.action for s in r.next_steps)
    assert r.evidence  # non-empty trail
    assert 0.0 <= r.confidence <= 1.0
    assert r.explanation


async def test_entities_raise_confidence(monkeypatch):
    bare = await _triage(_alert("Cobalt Strike beaconing"), monkeypatch)
    with_ents = await _triage(
        _alert("Cobalt Strike beaconing", ip=["1.2.3.4"], host=["ws1"]), monkeypatch
    )
    assert with_ents.result.confidence >= bare.result.confidence


async def test_unknown_is_low_confidence_and_investigate(monkeypatch):
    out = await _triage(_alert("nondescript event"), monkeypatch)
    assert out.result.typed_intent == TypedIntent.UNKNOWN
    assert out.result.disposition == TriageDisposition.INVESTIGATE
    assert out.result.confidence <= 0.4


# --------------------------------------------------------------------------- #
# Client-or-deterministic LLM path
# --------------------------------------------------------------------------- #


async def test_llm_path_used_when_client_registered(monkeypatch):
    from btagent_engine.llm import clear_llm_client, set_llm_client
    from btagent_shared.llm import LLMRequest, LLMResponse

    class _FakeClient:
        async def complete(self, request: LLMRequest) -> LLMResponse:
            return LLMResponse(
                content=(
                    '{"typed_intent":"malware_detected","proposed_severity":"critical",'
                    '"disposition":"escalate","confidence":0.9,"explanation":"LLM verdict",'
                    '"next_steps":[{"action":"Isolate review","rationale":"x"},'
                    '{"action":"Hash lookup","rationale":"y"}],"evidence":["edr hit"]}'
                ),
                provider="anthropic",
                model="claude-sonnet-4-6",
            )

    clear_llm_client()
    set_llm_client(_FakeClient())
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    try:
        out = await AlertTriageNode().run(
            AlertTriageInput(alert=_alert("ambiguous", severity=Severity.LOW)), _ctx()
        )
        assert out.mock_mode is False
        assert out.result.typed_intent == TypedIntent.MALWARE_DETECTED
        assert out.result.proposed_severity == Severity.CRITICAL
        assert out.result.severity_escalated is True  # critical > low
        assert out.result.explanation == "LLM verdict"
    finally:
        clear_llm_client()


async def test_llm_bad_response_falls_back_to_deterministic(monkeypatch):
    from btagent_engine.llm import clear_llm_client, set_llm_client
    from btagent_shared.llm import LLMRequest, LLMResponse

    class _BadClient:
        async def complete(self, request: LLMRequest) -> LLMResponse:
            return LLMResponse(content="sorry, no json", provider="x", model="y")

    clear_llm_client()
    set_llm_client(_BadClient())
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    try:
        out = await AlertTriageNode().run(
            AlertTriageInput(alert=_alert("Ransomware detected")), _ctx()
        )
        assert out.mock_mode is True  # fell back to deterministic
        assert out.result.typed_intent == TypedIntent.MALWARE_DETECTED
    finally:
        clear_llm_client()


async def test_non_mock_without_client_degrades(monkeypatch):
    from btagent_engine.llm import clear_llm_client

    clear_llm_client()
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    out = await AlertTriageNode().run(AlertTriageInput(alert=_alert("Ransomware detected")), _ctx())
    # No client registered -> deterministic, never raises.
    assert out.result.typed_intent == TypedIntent.MALWARE_DETECTED
