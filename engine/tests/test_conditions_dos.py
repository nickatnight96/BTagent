"""E5 / P4.5: condition-evaluator DoS siblings of the fixed ``**``/``*`` class.

``ast.Mod`` was allowed while the sequence guard checked ``ast.Mult`` only —
``'%50000000d' % 1`` allocates 50 MB in one expression and a bigger width is a
one-expression OOM. Also: ``RecursionError``/``MemoryError`` escaped the
documented single-error contract (the executor catches only
``ConditionEvaluationError``).
"""

from __future__ import annotations

import pytest

from btagent_engine.runtime.conditions import (
    ConditionEvaluationError,
    evaluate_condition,
)


def test_printf_format_dos_is_blocked():
    with pytest.raises(ConditionEvaluationError, match="printf-style"):
        evaluate_condition("'%50000000d' % 1", {})


def test_printf_format_blocked_via_context_string():
    """The format string arriving from workflow context is the realistic path."""
    with pytest.raises(ConditionEvaluationError, match="printf-style"):
        evaluate_condition("fmt % 1", {"fmt": "%2000000000d"})


def test_numeric_modulo_still_works():
    assert evaluate_condition("10 % 3", {}) == 1
    assert evaluate_condition("n % 2 == 0", {"n": 4}) is True


def test_deep_nesting_raises_condition_error_not_recursion_error():
    depth = 100_000
    expression = "(" * depth + "1" + ")" * depth
    # Depending on the parser's own limits this may fail at parse or at visit;
    # both must surface as ConditionEvaluationError, never a raw RecursionError.
    with pytest.raises(ConditionEvaluationError):
        evaluate_condition(expression, {})


def test_deep_unary_nesting_raises_condition_error():
    expression = "not " * 50_000 + "True"
    with pytest.raises(ConditionEvaluationError):
        evaluate_condition(expression, {})
