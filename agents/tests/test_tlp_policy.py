"""Tests for the TLP egress policy registry + violation events (UC-7.2).

Substrate lives in ``btagent_shared.security.tlp_policy``; the egress gate
in ``btagent_shared.security.tlp`` now emits a ``tlp.violation_attempt``
event on every refusal. Tested from ``agents/tests`` because that suite
runs in CI (and there is no dedicated ``shared/tests`` runner) — same
convention as ``test_tlp_egress.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from btagent_shared.security.tlp import TLPViolation, assert_tlp_allows_egress
from btagent_shared.security.tlp_policy import (
    PolicyDecision,
    TLPPolicy,
    TLPPolicyAction,
    TLPViolationEvent,
    clear_violation_sink,
    emit_violation,
    evaluate_egress_policy,
    set_violation_sink,
    tlp_rank,
)
from btagent_shared.types.config import TLP


def _policy(**kw: object) -> TLPPolicy:
    base: dict[str, object] = {
        "id": "pol_1",
        "org_id": "org_test",
        "action": TLPPolicyAction.ALLOW,
    }
    base.update(kw)
    return TLPPolicy(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Baseline (no policies) — default-deny RED, allow below RED
# --------------------------------------------------------------------------- #


def test_baseline_red_is_denied():
    d = evaluate_egress_policy(tlp=TLP.RED, egress_kind="mcp_return")
    assert d.allowed is False
    assert d.action == TLPPolicyAction.DENY
    assert d.matched_policy_id is None
    assert "default-deny" in d.reason


@pytest.mark.parametrize("tlp", [TLP.WHITE, TLP.GREEN, TLP.AMBER, TLP.AMBER_STRICT])
def test_baseline_below_red_is_allowed(tlp):
    d = evaluate_egress_policy(tlp=tlp, egress_kind="event_emit")
    assert d.allowed is True
    assert d.effective_tlp == tlp
    assert d.matched_policy_id is None


# --------------------------------------------------------------------------- #
# Policy effects
# --------------------------------------------------------------------------- #


def test_allow_policy_permits_red():
    pol = _policy(action=TLPPolicyAction.ALLOW, applies_to_tlp=(TLP.RED,))
    d = evaluate_egress_policy(tlp=TLP.RED, egress_kind="stix_export", policies=[pol])
    assert d.allowed is True
    assert d.matched_policy_id == "pol_1"
    assert d.effective_tlp == TLP.RED


def test_deny_policy_blocks_otherwise_allowed_green():
    pol = _policy(action=TLPPolicyAction.DENY, applies_to_tlp=(TLP.GREEN,))
    d = evaluate_egress_policy(tlp=TLP.GREEN, egress_kind="event_emit", policies=[pol])
    assert d.allowed is False
    assert d.action == TLPPolicyAction.DENY


def test_deny_wins_over_allow_when_both_match():
    allow = _policy(id="allow", action=TLPPolicyAction.ALLOW)
    deny = _policy(id="deny", action=TLPPolicyAction.DENY)
    d = evaluate_egress_policy(tlp=TLP.RED, egress_kind="mcp_return", policies=[allow, deny])
    assert d.allowed is False
    assert d.matched_policy_id == "deny"


def test_downgrade_then_allow_lowers_effective_tlp():
    pol = _policy(
        action=TLPPolicyAction.DOWNGRADE_THEN_ALLOW,
        applies_to_tlp=(TLP.RED,),
        downgrade_to=TLP.AMBER,
    )
    d = evaluate_egress_policy(tlp=TLP.RED, egress_kind="mcp_return", policies=[pol])
    assert d.allowed is True
    assert d.effective_tlp == TLP.AMBER
    assert d.action == TLPPolicyAction.DOWNGRADE_THEN_ALLOW


def test_downgrade_never_raises_classification():
    # "downgrade" to a MORE restricted level is not honoured as a raise;
    # the egress is allowed but the classification stays at the original.
    pol = _policy(
        action=TLPPolicyAction.DOWNGRADE_THEN_ALLOW,
        applies_to_tlp=(TLP.GREEN,),
        downgrade_to=TLP.RED,
    )
    d = evaluate_egress_policy(tlp=TLP.GREEN, egress_kind="mcp_return", policies=[pol])
    assert d.allowed is True
    assert d.effective_tlp == TLP.GREEN


def test_downgrade_defaults_to_green_when_target_unset():
    pol = _policy(action=TLPPolicyAction.DOWNGRADE_THEN_ALLOW, applies_to_tlp=(TLP.RED,))
    d = evaluate_egress_policy(tlp=TLP.RED, egress_kind="mcp_return", policies=[pol])
    assert d.allowed is True
    assert d.effective_tlp == TLP.GREEN


# --------------------------------------------------------------------------- #
# Matching conditions
# --------------------------------------------------------------------------- #


def test_egress_kind_filter_scopes_policy():
    pol = _policy(
        action=TLPPolicyAction.ALLOW, applies_to_tlp=(TLP.RED,), egress_kinds=("stix_export",)
    )
    # Wrong channel -> policy doesn't apply -> baseline deny for RED.
    d = evaluate_egress_policy(tlp=TLP.RED, egress_kind="mcp_return", policies=[pol])
    assert d.allowed is False
    # Right channel -> allowed.
    d2 = evaluate_egress_policy(tlp=TLP.RED, egress_kind="stix_export", policies=[pol])
    assert d2.allowed is True


def test_applies_to_tlp_filter_scopes_policy():
    pol = _policy(action=TLPPolicyAction.ALLOW, applies_to_tlp=(TLP.AMBER_STRICT,))
    # RED not in applies_to_tlp -> baseline deny.
    assert (
        evaluate_egress_policy(tlp=TLP.RED, egress_kind="mcp_return", policies=[pol]).allowed
        is False
    )


def test_expired_policy_does_not_match():
    past = datetime.now(UTC) - timedelta(hours=1)
    pol = _policy(action=TLPPolicyAction.ALLOW, applies_to_tlp=(TLP.RED,), valid_until=past)
    d = evaluate_egress_policy(tlp=TLP.RED, egress_kind="mcp_return", policies=[pol])
    assert d.allowed is False  # expired -> baseline deny


def test_future_expiry_policy_still_matches():
    future = datetime.now(UTC) + timedelta(hours=1)
    pol = _policy(action=TLPPolicyAction.ALLOW, applies_to_tlp=(TLP.RED,), valid_until=future)
    assert (
        evaluate_egress_policy(tlp=TLP.RED, egress_kind="mcp_return", policies=[pol]).allowed
        is True
    )


def test_empty_conditions_match_any():
    pol = _policy(action=TLPPolicyAction.ALLOW)  # no egress_kinds, no applies_to_tlp
    assert evaluate_egress_policy(
        tlp=TLP.RED, egress_kind="knowledge_ingest", policies=[pol]
    ).allowed


def test_naive_valid_until_is_treated_as_utc():
    # A naive (tz-less) valid_until must not raise on comparison. Build it
    # without datetime.utcnow() (deprecated) by stripping the tzinfo.
    naive_future = (datetime.now(UTC) + timedelta(hours=1)).replace(tzinfo=None)
    pol = _policy(
        action=TLPPolicyAction.ALLOW,
        applies_to_tlp=(TLP.RED,),
        valid_until=naive_future,
    )
    d = evaluate_egress_policy(tlp=TLP.RED, egress_kind="mcp_return", policies=[pol])
    assert d.allowed is True


def test_tlp_rank_ordering():
    assert tlp_rank(TLP.WHITE) < tlp_rank(TLP.GREEN) < tlp_rank(TLP.AMBER)
    assert tlp_rank(TLP.AMBER) < tlp_rank(TLP.AMBER_STRICT) < tlp_rank(TLP.RED)


# --------------------------------------------------------------------------- #
# Violation sink + emission
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _clear_sink():
    clear_violation_sink()
    yield
    clear_violation_sink()


def test_emit_violation_noop_without_sink():
    # No sink registered -> must not raise.
    emit_violation(
        TLPViolationEvent(tlp=TLP.RED, egress_kind="mcp_return", channel="egress:mcp_return")
    )


def test_emit_violation_dispatches_to_sink():
    captured: list[TLPViolationEvent] = []
    set_violation_sink(captured.append)
    ev = TLPViolationEvent(tlp=TLP.RED, egress_kind="event_emit", channel="egress:event_emit")
    emit_violation(ev)
    assert captured == [ev]


def test_emit_violation_swallows_sink_errors():
    def _boom(_ev: TLPViolationEvent) -> None:
        raise RuntimeError("alerter down")

    set_violation_sink(_boom)
    # Must not propagate — alerting can never break enforcement.
    emit_violation(TLPViolationEvent(tlp=TLP.RED, egress_kind="mcp_return", channel="x"))


def test_egress_gate_emits_violation_on_context_red():
    captured: list[TLPViolationEvent] = []
    set_violation_sink(captured.append)
    with pytest.raises(TLPViolation):
        assert_tlp_allows_egress({"k": "v"}, "stix_export", TLP.RED, org_id="org_42")
    assert len(captured) == 1
    ev = captured[0]
    assert ev.event_type == "tlp.violation_attempt"
    assert ev.egress_kind == "stix_export"
    assert ev.channel == "egress:stix_export"
    assert ev.org_id == "org_42"
    assert ev.tlp == TLP.RED


def test_egress_gate_emits_violation_on_payload_red():
    captured: list[TLPViolationEvent] = []
    set_violation_sink(captured.append)
    payload = {"metadata": {"tlp": "red"}, "data": [1, 2, 3]}
    with pytest.raises(TLPViolation):
        assert_tlp_allows_egress(payload, "mcp_return")
    assert len(captured) == 1
    assert captured[0].egress_kind == "mcp_return"
    assert captured[0].org_id is None


def test_egress_gate_no_violation_on_allowed_payload():
    captured: list[TLPViolationEvent] = []
    set_violation_sink(captured.append)
    # GREEN context, no RED in payload -> allowed, no event.
    assert_tlp_allows_egress({"tlp": "green"}, "event_emit", TLP.GREEN)
    assert captured == []


def test_policy_decision_is_frozen():
    d = PolicyDecision(allowed=True, effective_tlp=TLP.GREEN, action=TLPPolicyAction.ALLOW)
    with pytest.raises((TypeError, ValueError)):
        d.allowed = False  # type: ignore[misc]
