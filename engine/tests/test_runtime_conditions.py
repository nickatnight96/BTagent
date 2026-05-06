"""Tests for the safe condition evaluator (Sprint 4D).

Exercises :mod:`btagent_engine.runtime.conditions` in isolation so we
can be sure the AST walker's allowlist holds without having to spin up
a full :class:`WorkflowExecutor`. End-to-end tests live in
``test_workflow_executor.py``.

Categories:

* ``Comparisons / arithmetic / boolean logic`` -- the happy path.
* ``Variable + attribute + subscript access`` -- mirrors the
  ``node['scorer'].field`` shape the executor exposes.
* ``Sandbox`` -- the fail-shut paths (dunder access, arbitrary calls,
  ``**``, missing variables, syntax errors).
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from btagent_engine.runtime.conditions import (
    ConditionEvaluationError,
    build_condition_context,
    coerce_to_branch,
    evaluate_condition,
)

# --------------------------------------------------------------------------- #
# Comparisons + arithmetic + booleans
# --------------------------------------------------------------------------- #


def test_numeric_comparison_greater_than_returns_bool():
    assert evaluate_condition("5 > 3", {}) is True
    assert evaluate_condition("3 > 5", {}) is False


def test_numeric_comparison_less_than_and_eq():
    assert evaluate_condition("1 < 2", {}) is True
    assert evaluate_condition("2 == 2", {}) is True
    assert evaluate_condition("2 != 3", {}) is True
    assert evaluate_condition("3 >= 3", {}) is True
    assert evaluate_condition("3 <= 2", {}) is False


def test_boolean_and_or_not_short_circuit():
    # All three short-circuit paths exercised.
    assert evaluate_condition("True and False", {}) is False
    assert evaluate_condition("True or False", {}) is True
    assert evaluate_condition("not False", {}) is True
    # Short-circuit: the right-hand side would raise on a missing variable
    # if it were evaluated -- it shouldn't be.
    assert evaluate_condition("False and missing", {}) is False
    assert evaluate_condition("True or missing", {}) is True


def test_arithmetic_basic_ops():
    assert evaluate_condition("2 + 3", {}) == 5
    assert evaluate_condition("10 - 4", {}) == 6
    assert evaluate_condition("3 * 4", {}) == 12
    assert evaluate_condition("10 / 4", {}) == 2.5
    assert evaluate_condition("10 // 3", {}) == 3
    assert evaluate_condition("10 % 3", {}) == 1


def test_string_equality():
    assert evaluate_condition("'critical' == 'critical'", {}) is True
    assert evaluate_condition("'high' == 'low'", {}) is False


def test_in_operator_against_literal_list():
    ctx = {"severity": "high"}
    assert evaluate_condition("severity in ['high', 'critical']", ctx) is True
    assert evaluate_condition("severity in ['low', 'medium']", ctx) is False


# --------------------------------------------------------------------------- #
# Variable / attribute / subscript access
# --------------------------------------------------------------------------- #


class _ScoreModel(BaseModel):
    score: float
    severity: str
    tags: list[str] = []


def test_variable_lookup_against_context():
    assert evaluate_condition("x > 0.5", {"x": 0.7}) is True
    assert evaluate_condition("x > 0.5", {"x": 0.3}) is False


def test_subscript_access_on_node_dict():
    """``node['triage']`` style lookup -- the canonical condition shape."""
    state_outputs = {"triage": _ScoreModel(score=0.8, severity="critical")}
    ctx = build_condition_context(state_outputs)
    # build_condition_context flattens to dicts, so attribute style works
    # via the dict-key fallback in _visit_attribute.
    assert evaluate_condition("node['triage'].score > 0.7", ctx) is True
    # And so does pure subscript style.
    assert evaluate_condition("node['triage']['severity'] == 'critical'", ctx) is True


def test_len_of_list_field():
    state_outputs = {"enrich": _ScoreModel(score=0.0, severity="low", tags=["a", "b", "c"])}
    ctx = build_condition_context(state_outputs)
    assert evaluate_condition("len(node['enrich'].tags) > 2", ctx) is True
    assert evaluate_condition("len(node['enrich'].tags) == 3", ctx) is True


# --------------------------------------------------------------------------- #
# Sandbox -- things that MUST fail
# --------------------------------------------------------------------------- #


def test_missing_variable_raises_condition_error_not_keyerror():
    """The executor catches ConditionEvaluationError specifically; KeyError would leak."""
    with pytest.raises(ConditionEvaluationError) as ei:
        evaluate_condition("missing_var > 1", {})
    assert "missing_var" in str(ei.value)
    # Ensure it's NOT a KeyError or NameError leaking through.
    assert not isinstance(ei.value, (KeyError, NameError))


def test_dunder_attribute_access_is_blocked():
    """``foo.__class__`` is the standard sandbox-escape primitive -- must fail."""

    class _Holder:
        pass

    ctx = {"obj": _Holder()}
    with pytest.raises(ConditionEvaluationError) as ei:
        evaluate_condition("obj.__class__", ctx)
    assert "__class__" in str(ei.value)


def test_underscore_prefixed_attribute_access_is_blocked():
    """All single-underscore (private) attrs are blocked, not just dunders."""

    class _Holder:
        _secret = "shh"

    ctx = {"obj": _Holder()}
    with pytest.raises(ConditionEvaluationError):
        evaluate_condition("obj._secret", ctx)


def test_power_operator_is_rejected_with_specific_message():
    """``**`` is the canonical safe-eval DoS vector -- explicitly disallowed."""
    with pytest.raises(ConditionEvaluationError) as ei:
        evaluate_condition("2 ** 99999999", {})
    assert "Power" in str(ei.value) or "power" in str(ei.value)


def test_arbitrary_function_call_is_rejected():
    """Only the explicit allowlist (len/min/max) may be called."""
    with pytest.raises(ConditionEvaluationError) as ei:
        evaluate_condition("print('hi')", {})
    assert "allowlist" in str(ei.value) or "print" in str(ei.value)


def test_method_call_is_rejected():
    """``foo.bar()`` would re-open attribute-walk; only bare-name calls allowed."""
    ctx = {"s": "hello"}
    with pytest.raises(ConditionEvaluationError):
        evaluate_condition("s.upper()", ctx)


def test_lambda_is_rejected():
    """Lambdas would let an attacker construct arbitrary callables."""
    with pytest.raises(ConditionEvaluationError):
        evaluate_condition("(lambda: 1)()", {})


def test_list_comprehension_is_rejected():
    """Comprehensions could hide arbitrary computation -- block."""
    with pytest.raises(ConditionEvaluationError):
        evaluate_condition("[x for x in range(10)]", {})


def test_assignment_expression_is_rejected():
    """Walrus (``:=``) is parseable; we don't want side-effecting expressions."""
    with pytest.raises(ConditionEvaluationError):
        evaluate_condition("(x := 1)", {})


def test_empty_expression_raises():
    with pytest.raises(ConditionEvaluationError):
        evaluate_condition("   ", {})


def test_syntax_error_in_expression():
    with pytest.raises(ConditionEvaluationError) as ei:
        evaluate_condition("1 +", {})
    assert "syntax" in str(ei.value).lower()


def test_subscript_with_dynamic_index_is_rejected():
    """Constant indices only -- a computed key has no legitimate routing use."""
    ctx = {"d": {"a": 1}, "k": "a"}
    with pytest.raises(ConditionEvaluationError):
        evaluate_condition("d[k]", ctx)


def test_keyword_args_to_allowed_call_rejected():
    """Even calls to allowlisted callables don't accept kwargs."""
    with pytest.raises(ConditionEvaluationError):
        evaluate_condition("max(1, 2, key=None)", {})


# --------------------------------------------------------------------------- #
# Allowed callables: min / max / len
# --------------------------------------------------------------------------- #


def test_min_max_len_callables_work():
    assert evaluate_condition("min(3, 1, 2)", {}) == 1
    assert evaluate_condition("max(3, 1, 2)", {}) == 3
    assert evaluate_condition("len('abcd')", {}) == 4


# --------------------------------------------------------------------------- #
# Branch coercion helper
# --------------------------------------------------------------------------- #


def test_coerce_to_branch_for_bools():
    assert coerce_to_branch(True) == "true"
    assert coerce_to_branch(False) == "false"


def test_coerce_to_branch_for_other_values():
    assert coerce_to_branch("critical") == "critical"
    assert coerce_to_branch(42) == "42"


# --------------------------------------------------------------------------- #
# build_condition_context
# --------------------------------------------------------------------------- #


def test_build_context_flattens_pydantic_outputs_to_dicts():
    state_outputs = {"triage": _ScoreModel(score=0.9, severity="critical")}
    ctx = build_condition_context(state_outputs)
    assert "node" in ctx
    assert ctx["node"]["triage"]["score"] == 0.9
    assert ctx["node"]["triage"]["severity"] == "critical"


def test_build_context_handles_dict_outputs():
    """Hand-built test states (no Pydantic) still flatten cleanly."""
    state_outputs = {"raw": {"x": 1}}
    ctx = build_condition_context(state_outputs)
    assert ctx["node"]["raw"] == {"x": 1}
