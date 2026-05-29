"""Tests for ResponsePlanNode (EPIC-3 UC-3.2)."""

from __future__ import annotations

from btagent_engine.node import NodeContext
from btagent_engine.reasoning import ResponsePlanInput, ResponsePlanNode, ResponsePlanOutput
from btagent_shared.types.enums import Severity
from btagent_shared.types.response import ResponseActionType, ResponseCategory
from btagent_shared.types.triage import TypedIntent


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_resp", org_id="org_test")


async def _plan(
    intent: TypedIntent, monkeypatch, *, severity: Severity = Severity.HIGH, **entities
) -> ResponsePlanOutput:
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await ResponsePlanNode().run(
        ResponsePlanInput(
            typed_intent=intent,
            severity=severity,
            entities={k: list(v) for k, v in entities.items()},
        ),
        _ctx(),
    )
    assert isinstance(out, ResponsePlanOutput)
    assert out.mock_mode is True
    return out


async def test_malware_plan_isolates_host(monkeypatch):
    out = await _plan(TypedIntent.MALWARE_DETECTED, monkeypatch, host=["WS-12"])
    actions = out.plan.tactical_steps
    types = {a.action_type for a in actions}
    assert ResponseActionType.ISOLATE_HOST in types
    assert ResponseActionType.OPEN_TICKET in types
    isolate = next(a for a in actions if a.action_type == ResponseActionType.ISOLATE_HOST)
    assert isolate.target == "WS-12"
    assert isolate.destructive is True
    assert isolate.requires_approval is True
    assert isolate.rollback and "WS-12" in isolate.rollback


async def test_destructive_requires_approval_readonly_does_not(monkeypatch):
    out = await _plan(TypedIntent.MALWARE_DETECTED, monkeypatch, host=["h1"])
    for a in out.plan.tactical_steps:
        if a.category == ResponseCategory.CONTAIN:
            assert a.destructive is True
            assert a.requires_approval is True
            assert a.rollback  # reversible containment carries a rollback
        else:
            # investigate / document are read-only / low-impact
            assert a.requires_approval is False


async def test_entities_fan_out_to_actions(monkeypatch):
    out = await _plan(TypedIntent.C2_BEACONING, monkeypatch, ip=["1.1.1.1", "2.2.2.2"], host=["h1"])
    block_ips = [a for a in out.plan.tactical_steps if a.action_type == ResponseActionType.BLOCK_IP]
    assert {a.target for a in block_ips} == {"1.1.1.1", "2.2.2.2"}


async def test_suspicious_login_disables_account(monkeypatch):
    out = await _plan(TypedIntent.SUSPICIOUS_LOGIN, monkeypatch, user=["alice@corp"])
    disable = next(
        a for a in out.plan.tactical_steps if a.action_type == ResponseActionType.DISABLE_ACCOUNT
    )
    assert disable.target == "alice@corp"
    assert disable.connector == "okta"
    assert disable.rollback


async def test_strategic_goal_and_containment_window(monkeypatch):
    out = await _plan(
        TypedIntent.MALWARE_DETECTED, monkeypatch, severity=Severity.CRITICAL, host=["h1"]
    )
    assert out.plan.strategic_goal
    assert out.plan.estimated_containment_minutes == 5
    assert "5 minutes" in out.plan.strategic_goal


async def test_benign_has_no_contain_step(monkeypatch):
    out = await _plan(TypedIntent.BENIGN, monkeypatch)
    assert all(a.category != ResponseCategory.CONTAIN for a in out.plan.tactical_steps)


async def test_no_entity_still_produces_targeted_step_placeholder(monkeypatch):
    # Malware with no host entity still proposes isolation (target placeholder).
    out = await _plan(TypedIntent.MALWARE_DETECTED, monkeypatch)
    isolate = next(
        a for a in out.plan.tactical_steps if a.action_type == ResponseActionType.ISOLATE_HOST
    )
    assert isolate.target == ""
    assert "affected host" in isolate.description


# --------------------------------------------------------------------------- #
# LLM refines the narrative ONLY — tactical actions stay deterministic
# --------------------------------------------------------------------------- #


async def test_llm_refines_narrative_only(monkeypatch):
    from btagent_engine.llm import clear_llm_client, set_llm_client
    from btagent_shared.llm import LLMRequest, LLMResponse

    class _FakeClient:
        async def complete(self, request: LLMRequest) -> LLMResponse:
            return LLMResponse(
                content='{"strategic_goal":"LLM goal","rationale":"LLM rationale"}',
                provider="anthropic",
                model="claude-sonnet-4-6",
            )

    clear_llm_client()
    set_llm_client(_FakeClient())
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    try:
        det = await ResponsePlanNode().run(
            ResponsePlanInput(typed_intent=TypedIntent.MALWARE_DETECTED, entities={"host": ["h1"]}),
            _ctx(),
        )
        # det ran with client set but we want the deterministic action list to
        # compare — rebuild via mock for the baseline.
        monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
        baseline = await ResponsePlanNode().run(
            ResponsePlanInput(typed_intent=TypedIntent.MALWARE_DETECTED, entities={"host": ["h1"]}),
            _ctx(),
        )
        assert det.mock_mode is False
        assert det.plan.strategic_goal == "LLM goal"
        assert det.plan.rationale == "LLM rationale"
        # Safety: the LLM did NOT change the tactical actions.
        assert [a.action_type for a in det.plan.tactical_steps] == [
            a.action_type for a in baseline.plan.tactical_steps
        ]
        assert [a.destructive for a in det.plan.tactical_steps] == [
            a.destructive for a in baseline.plan.tactical_steps
        ]
    finally:
        clear_llm_client()


async def test_llm_bad_response_falls_back(monkeypatch):
    from btagent_engine.llm import clear_llm_client, set_llm_client
    from btagent_shared.llm import LLMRequest, LLMResponse

    class _BadClient:
        async def complete(self, request: LLMRequest) -> LLMResponse:
            return LLMResponse(content="no json", provider="x", model="y")

    clear_llm_client()
    set_llm_client(_BadClient())
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    try:
        out = await ResponsePlanNode().run(
            ResponsePlanInput(typed_intent=TypedIntent.C2_BEACONING, entities={"ip": ["9.9.9.9"]}),
            _ctx(),
        )
        assert out.mock_mode is True  # deterministic narrative
        assert any(a.action_type == ResponseActionType.BLOCK_IP for a in out.plan.tactical_steps)
    finally:
        clear_llm_client()
