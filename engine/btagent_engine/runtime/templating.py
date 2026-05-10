"""``{{ expr }}`` placeholder rendering for WorkflowNode config strings.

Sprint 5B. The compiler stashes YAML ``arguments`` blocks verbatim onto
``WorkflowNode.config``. Production templates contain Jinja-style
placeholders like ``"{{ alert_text }}"`` or
``"{{ node['triage'].severity }}"`` that need to be replaced with the
runtime values before the next Node receives them.

Rather than depending on Jinja2 (extra transitive surface) we reuse
Sprint 4D's safe AST-walking evaluator -- the placeholder body is
evaluated as a single expression in the same restricted namespace
that DecisionNode conditions use. Everything outside ``{{ ... }}``
passes through verbatim.

What the renderer is NOT:

* Not a full template language. No loops, no conditionals, no
  filters, no whitespace control. One expression per placeholder.
* Not silently lenient. A missing variable raises
  ``ConditionEvaluationError`` -- the workflow author needs to know
  their reference is wrong, not have it become "None" downstream.
* Not recursive. ``"{{ '{{ x }}' }}"`` is treated as the literal
  string ``'{{ x }}'``, not a re-render.
"""

from __future__ import annotations

import re
from typing import Any

from btagent_engine.runtime.conditions import evaluate_condition

# Placeholder pattern: ``{{`` + (lazy anything) + ``}}``. The lazy match
# means ``"{{ a }} and {{ b }}"`` parses as two placeholders, not one
# greedy span. Whitespace inside the braces is stripped before eval.
_PLACEHOLDER_RE = re.compile(r"\{\{\s*(.*?)\s*\}\}", re.DOTALL)


def render_template(
    template: str,
    context: dict[str, Any],
) -> str:
    """Render a single string by replacing every ``{{ expr }}`` placeholder
    with ``str(evaluate_condition(expr, context))``.

    Strings without ``{{`` are returned unchanged (fast path).

    Raises ``ConditionEvaluationError`` if any placeholder body fails to
    evaluate -- mirrors the DecisionNode condition behaviour.
    """
    if "{{" not in template:
        return template

    def _sub(match: re.Match[str]) -> str:
        expr = match.group(1)
        if not expr:
            # ``{{ }}`` -- empty placeholder. Treat as a literal so the
            # template author sees the bug (the rendered output keeps
            # the empty braces) instead of silently producing "".
            return match.group(0)
        value = evaluate_condition(expr, context)
        return str(value)

    return _PLACEHOLDER_RE.sub(_sub, template)


def render_payload(
    payload: Any,
    context: dict[str, Any],
) -> Any:
    """Recursively render every string in *payload* against *context*.

    Walks dicts, lists, and tuples. Non-string scalars (numbers, bools,
    None) pass through unchanged. The structure is reconstructed -- the
    input is never mutated, so callers can safely render a
    ``WorkflowNode.config`` shared between executions.
    """
    if isinstance(payload, str):
        return render_template(payload, context)
    if isinstance(payload, dict):
        return {k: render_payload(v, context) for k, v in payload.items()}
    if isinstance(payload, list):
        return [render_payload(item, context) for item in payload]
    if isinstance(payload, tuple):
        return tuple(render_payload(item, context) for item in payload)
    return payload


__all__ = ["render_payload", "render_template"]
