"""Tests for the per-entity classification cost gate (#114 Phase A, task E).

The gate caps the IntentClassifier's per-entity LLM spend at <$0.10/entity by
wrapping the injected ``LLMCallable``. Two layers:

* the budget primitive — accrual, per-entity isolation, and the hard refusal
  once an entity reaches its cap;
* the ``classify_outlier_within_budget`` integration — an over-budget entity
  simply stops being classified (the classifier degrades the raised budget
  error to a skip), while a fresh entity is unaffected.
"""

from datetime import UTC, datetime, timedelta

import pytest
from btagent_shared.types.behavioral import EntityKind, IntentLabel, ProfileType

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.services import behavioral_service as svc
from btagent_backend.services.behavioral_cost_gate import (
    DEFAULT_MAX_COST_USD,
    BehavioralCostBudgetExceeded,
    EntityClassificationBudget,
    classify_outlier_within_budget,
    entity_key_for,
    estimate_call_cost,
)

_SYS = "You are a behavioral threat-hunting analyst. Rate the intent."
_USR = "<external-data>\nentity: host:WS\nflagged event: winword.exe>powershell.exe -enc\n</external-data>"
_OUT = '{"intent": "malicious", "rationale": "encoded PowerShell from Office"}'


def _fixed_llm(reply: str = _OUT):
    async def _call(system: str, user: str, tier: str) -> str:
        return reply

    return _call


def _keyword_llm():
    """FAST screen rates suspicious/malicious by keyword; STANDARD confirms."""

    async def _call(system: str, user: str, tier: str) -> str:
        strong = any(
            k in user.lower()
            for k in ("-enc", "certutil", "mshta", "downloadstring", "iex", "frombase64")
        )
        if tier == "fast":
            return (
                '{"intent": "malicious", "rationale": "strong LotL indicator"}'
                if strong
                else '{"intent": "suspicious", "rationale": "anomalous lineage"}'
            )
        return '{"intent": "malicious", "rationale": "confirmed LotL"}'

    return _call


# --------------------------------------------------------------------------- #
# budget primitive
# --------------------------------------------------------------------------- #


def test_default_cap_is_ten_cents():
    assert DEFAULT_MAX_COST_USD == 0.10
    assert EntityClassificationBudget().max_cost_usd == 0.10


def test_standard_tier_costs_more_than_fast():
    fast = estimate_call_cost("fast", _SYS, _USR, _OUT)
    standard = estimate_call_cost("standard", _SYS, _USR, _OUT)
    assert 0.0 < fast < standard  # Haiku screen is cheaper than the Sonnet pass


def test_charge_accrues_and_flips_over_budget():
    budget = EntityClassificationBudget(max_cost_usd=0.05)
    assert budget.spent("host:X") == 0.0
    assert budget.remaining("host:X") == 0.05
    budget.charge("host:X", 0.03)
    assert budget.spent("host:X") == pytest.approx(0.03)
    assert not budget.over_budget("host:X")
    budget.charge("host:X", 0.03)
    assert budget.over_budget("host:X")
    assert budget.remaining("host:X") == 0.0


async def test_guard_meters_and_blocks_per_entity():
    per_call = estimate_call_cost("fast", _SYS, _USR, _OUT)
    assert per_call > 0.0
    # Cap admits three calls (0, 1x, 2x all < 2.5x); the fourth is refused.
    budget = EntityClassificationBudget(max_cost_usd=2.5 * per_call)

    guard_a = budget.guard("host:A", _fixed_llm())
    guard_b = budget.guard("host:B", _fixed_llm())

    for _ in range(3):
        assert await guard_a(_SYS, _USR, "fast") == _OUT
    assert budget.over_budget("host:A")
    with pytest.raises(BehavioralCostBudgetExceeded) as exc:
        await guard_a(_SYS, _USR, "fast")
    assert exc.value.entity_key == "host:A"

    # A different entity keeps its own untouched ledger.
    assert await guard_b(_SYS, _USR, "fast") == _OUT
    assert budget.spent("host:B") == pytest.approx(per_call)
    assert not budget.over_budget("host:B")


# --------------------------------------------------------------------------- #
# classify_outlier_within_budget integration
# --------------------------------------------------------------------------- #


async def _make_outlier(db, canonical_id: str):
    entity = await svc.upsert_entity(
        db, org_id=DEFAULT_ORG_ID, kind=EntityKind.HOST, canonical_id=canonical_id
    )
    now = datetime.now(UTC)
    await svc.build_baseline(
        db,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        vectors=[[1.0, 0.0, 0.0, 0.0], [0.98, 0.02, 0.0, 0.0]],
        pattern_keys=["explorer.exe>cmd.exe", "explorer.exe>cmd.exe"],
        window_start=now - timedelta(days=30),
        window_end=now,
    )
    outlier = await svc.detect_outlier(
        db,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        event_id=f"evt_{canonical_id}",
        event_vector=[0.0, 0.0, 0.0, 1.0],
        event_pattern_key="winword.exe>powershell.exe -enc",
        raw_event_excerpt="winword.exe -> powershell.exe -nop -w hidden -enc SQBFAFgA",
    )
    assert outlier is not None
    return entity, outlier


async def test_classify_within_budget_normal_path(db_session):
    entity, outlier = await _make_outlier(db_session, "WS-COST-OK")
    budget = EntityClassificationBudget()  # default $0.10 cap

    classified = await classify_outlier_within_budget(
        db_session, outlier_id=outlier.id, budget=budget, llm=_keyword_llm()
    )
    assert classified is not None
    assert classified.intent_label in {IntentLabel.SUSPICIOUS.value, IntentLabel.MALICIOUS.value}

    key = entity_key_for(entity.kind, entity.canonical_id)
    spent = budget.spent(key)
    assert 0.0 < spent < DEFAULT_MAX_COST_USD  # one classification stays well under budget


async def test_classify_skipped_when_entity_over_budget(db_session):
    entity, outlier = await _make_outlier(db_session, "WS-COST-OVER")
    budget = EntityClassificationBudget()
    key = entity_key_for(entity.kind, entity.canonical_id)
    # Simulate an entity that has already burned its whole classification budget.
    budget.charge(key, DEFAULT_MAX_COST_USD)

    classified = await classify_outlier_within_budget(
        db_session, outlier_id=outlier.id, budget=budget, llm=_keyword_llm()
    )
    # The screen call is refused -> the classifier degrades to a skip (no verdict).
    assert classified is None
    refreshed = await svc.get_outlier(db_session, outlier.id)
    assert refreshed.intent_label is None

    # A different entity with the SAME budget object is unaffected (isolation).
    other_entity, other_outlier = await _make_outlier(db_session, "WS-COST-OTHER")
    other = await classify_outlier_within_budget(
        db_session, outlier_id=other_outlier.id, budget=budget, llm=_keyword_llm()
    )
    assert other is not None
    assert other.intent_label in {IntentLabel.SUSPICIOUS.value, IntentLabel.MALICIOUS.value}
