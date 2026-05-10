"""Tests for ``btagent_engine.runtime.templating``.

The templating module is a thin wrapper around Sprint 4D's expression
evaluator -- the security tests for the evaluator itself live in
``test_runtime_conditions.py``. These tests cover the placeholder
parsing, payload-walk recursion, and the end-to-end integration with
the executor's config-merge step.
"""

from __future__ import annotations

import pytest

from btagent_engine.runtime.conditions import ConditionEvaluationError
from btagent_engine.runtime.templating import render_payload, render_template

# --------------------------------------------------------------------------- #
# render_template
# --------------------------------------------------------------------------- #


def test_string_without_placeholder_passes_through():
    assert render_template("just a literal", {}) == "just a literal"


def test_single_substitution():
    assert render_template("Hello {{ name }}", {"name": "world"}) == "Hello world"


def test_multiple_substitutions_in_one_string():
    rendered = render_template("{{ x }} and {{ y }}", {"x": 1, "y": 2})
    assert rendered == "1 and 2"


def test_whitespace_inside_braces_is_stripped():
    """Authors might write ``{{x}}`` or ``{{   x   }}``; both work."""
    assert render_template("{{x}}", {"x": "ok"}) == "ok"
    assert render_template("{{   x   }}", {"x": "ok"}) == "ok"


def test_missing_variable_raises():
    with pytest.raises(ConditionEvaluationError):
        render_template("{{ missing }}", {})


def test_empty_placeholder_left_literal():
    """``{{ }}`` is treated as literal so the bug surfaces in the
    rendered output rather than producing a silent empty string."""
    assert render_template("a{{ }}b", {}) == "a{{ }}b"


def test_lazy_match_does_not_span_placeholders():
    """Two adjacent placeholders are two substitutions, not one greedy
    match across them."""
    rendered = render_template("[{{ a }}][{{ b }}]", {"a": 1, "b": 2})
    assert rendered == "[1][2]"


def test_supports_subscript_via_node_namespace():
    """Mirrors how DecisionNode conditions reference upstream outputs."""
    ctx = {"node": {"triage": {"severity": "high"}}}
    rendered = render_template("Severity is {{ node['triage'].severity }}", ctx)
    assert rendered == "Severity is high"


def test_dunder_attribute_blocked_at_renderer_too():
    """Sprint 4D's evaluator forbids dunder access; the renderer
    inherits that restriction (no ``__class__`` escape)."""
    with pytest.raises(ConditionEvaluationError):
        render_template("{{ x.__class__ }}", {"x": "anything"})


def test_no_recursive_render():
    """Output of a rendered placeholder is NOT re-scanned. A value that
    happens to contain ``{{`` is inserted literally."""
    rendered = render_template("{{ payload }}", {"payload": "{{ inner }}"})
    assert rendered == "{{ inner }}"


# --------------------------------------------------------------------------- #
# render_payload (recursive walk)
# --------------------------------------------------------------------------- #


def test_render_payload_walks_dict():
    payload = {"prompt": "Hello {{ name }}", "max_tokens": 64}
    rendered = render_payload(payload, {"name": "Bob"})
    assert rendered == {"prompt": "Hello Bob", "max_tokens": 64}


def test_render_payload_walks_list():
    payload = [{"role": "user", "content": "{{ q }}"}]
    rendered = render_payload(payload, {"q": "ping"})
    assert rendered == [{"role": "user", "content": "ping"}]


def test_render_payload_walks_nested_messages_array():
    """Real-shape: LLMCallInput's messages list with rendered content."""
    payload = {
        "messages": [
            {"role": "system", "content": "You are an analyst."},
            {"role": "user", "content": "Look at <external-data>{{ alert_text }}</external-data>"},
        ],
        "model": "claude-haiku",
        "max_tokens": 256,
    }
    ctx = {"alert_text": "ransom note dropped"}
    rendered = render_payload(payload, ctx)
    assert rendered["messages"][1]["content"] == (
        "Look at <external-data>ransom note dropped</external-data>"
    )
    assert rendered["model"] == "claude-haiku"
    assert rendered["max_tokens"] == 256


def test_render_payload_passes_through_non_strings():
    """ints / floats / None / bools survive unchanged."""
    payload = {"x": 1, "y": 1.5, "z": None, "active": True}
    assert render_payload(payload, {}) == payload


def test_render_payload_does_not_mutate_input():
    """Workflow ``config`` dicts are shared between executions; the
    renderer must not mutate them in place."""
    original = {"prompt": "Hello {{ name }}"}
    snapshot = dict(original)
    render_payload(original, {"name": "Alice"})
    assert original == snapshot


def test_render_payload_handles_tuples():
    """Tuples are reconstructed (engine doesn't use them in workflow
    configs but defensive coverage prevents future regressions)."""
    rendered = render_payload(("static", "{{ x }}"), {"x": "dyn"})
    assert rendered == ("static", "dyn")
