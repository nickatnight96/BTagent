"""Safe condition-expression evaluator for DecisionNode routing.

Sprint 4D. The compiler stashes a playbook's raw ``condition`` string in
``WorkflowNode.config`` (e.g. ``"node['triage'].score > 0.7"``) so the
runtime can evaluate it against upstream node outputs and feed the
result into :class:`btagent_engine.compiler.steps.DecisionNode`. This
module is the evaluator -- isolated from ``executor.py`` so it can be
unit-tested in isolation and to keep the executor focused on graph
walking.

Design call: **stdlib ``ast`` walker, no third-party deps.** The
engine's runtime dependencies today are pydantic + pyyaml; pulling in
``simpleeval`` (or its transitive deps) just to support a tiny
expression language adds supply-chain surface for no functional win
over a ~100-line walker that handles only the constructs we actually
need. The walker explicitly whitelists:

* ``ast.Compare`` -- ``<``, ``<=``, ``==``, ``!=``, ``>=``, ``>``,
  ``in``, ``not in``.
* ``ast.BoolOp`` -- ``and``, ``or``.
* ``ast.UnaryOp`` -- ``not``, unary ``-``, unary ``+``.
* ``ast.BinOp`` -- ``+``, ``-``, ``*``, ``/``, ``//``, ``%`` (no
  ``**`` -- power is the classic DoS vector for safe-eval crates).
* ``ast.Name`` -- variable lookup against the supplied context.
* ``ast.Subscript`` -- ``node['triage']`` style lookup. Only constant
  indices.
* ``ast.Attribute`` -- ``foo.bar`` lookup. Dunder names are rejected
  to block attribute-walk escapes (``__class__.__bases__`` etc).
* ``ast.Constant`` -- numeric / string / bool / None literals.
* ``ast.Call`` -- only against the explicit allowlist (``len``,
  ``min``, ``max``). No keyword args.
* ``ast.List`` / ``ast.Tuple`` -- literal collections, useful for
  ``severity in ['high', 'critical']``.

Anything else (lambdas, comprehensions, ``**``, ``f``-strings, walrus,
imports, generators, slicing, ...) raises
:class:`ConditionEvaluationError`. The error message names the
construct and the column so playbook authors get actionable feedback.
"""

from __future__ import annotations

import ast
from typing import Any

# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class ConditionEvaluationError(ValueError):
    """Raised when a condition string cannot be safely evaluated.

    Covers parse failures, disallowed AST nodes, missing variables,
    type errors at evaluation time, and calls to non-allowlisted
    callables. ``expression`` carries the original source so the caller
    can include it in higher-level error messages without having to
    plumb it through separately.
    """

    def __init__(self, message: str, *, expression: str | None = None) -> None:
        super().__init__(message)
        self.expression = expression


# --------------------------------------------------------------------------- #
# Allowlists
# --------------------------------------------------------------------------- #

# Only these callables can be invoked from a condition. Keeping the set
# tiny is deliberate -- each entry is an explicit decision, not a
# default. ``len`` covers the "at least one" / "more than N" idiom for
# list outputs; ``min`` / ``max`` cover scoring conditions like
# ``max(node['triage'].scores) > 0.7``.
_ALLOWED_CALLABLES: dict[str, Any] = {
    "len": len,
    "min": min,
    "max": max,
}

# Mapping ast comparison op -> Python operator function. Done explicitly
# (rather than `eval(repr(op))`) so we never go anywhere near `eval`.
_COMPARE_OPS: dict[type[ast.cmpop], Any] = {
    ast.Lt: lambda a, b: a < b,
    ast.LtE: lambda a, b: a <= b,
    ast.Eq: lambda a, b: a == b,
    ast.NotEq: lambda a, b: a != b,
    ast.GtE: lambda a, b: a >= b,
    ast.Gt: lambda a, b: a > b,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}

_BIN_OPS: dict[type[ast.operator], Any] = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.Div: lambda a, b: a / b,
    ast.FloorDiv: lambda a, b: a // b,
    ast.Mod: lambda a, b: a % b,
    # NB: ast.Pow deliberately omitted -- ``2 ** 99999999`` is a one-line
    # CPU/memory DoS even with no other suspicious constructs in the
    # expression.
}

_UNARY_OPS: dict[type[ast.unaryop], Any] = {
    ast.Not: lambda a: not a,
    ast.USub: lambda a: -a,
    ast.UAdd: lambda a: +a,
}


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


def evaluate_condition(expression: str, context: dict[str, Any]) -> Any:
    """Safely evaluate *expression* with *context* providing variable bindings.

    The expression language is a tiny subset of Python (see module docstring).
    ``context`` keys are the names visible to the expression -- typically
    ``{"node": <flattened-state-outputs>}`` so ``node['triage'].score``
    walks the upstream node's validated output.

    Raises :class:`ConditionEvaluationError` on any failure. Never raises
    ``KeyError`` / ``AttributeError`` / ``TypeError`` directly -- those
    are wrapped so the caller (the WorkflowExecutor) gets a single
    error type to catch.
    """
    if not isinstance(expression, str):
        raise ConditionEvaluationError(
            f"Condition must be a string, got {type(expression).__name__}",
            expression=None,
        )
    if not expression.strip():
        raise ConditionEvaluationError(
            "Condition expression is empty", expression=expression
        )

    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise ConditionEvaluationError(
            f"Condition syntax error: {exc.msg}", expression=expression
        ) from exc

    evaluator = _Evaluator(context, expression)
    return evaluator.visit(tree.body)


# --------------------------------------------------------------------------- #
# Walker
# --------------------------------------------------------------------------- #


class _Evaluator:
    """AST walker that evaluates the allowlisted node types and rejects all others.

    Holds the context + source string so error messages can quote both;
    instance methods rather than free functions so the dispatch table
    closes over ``self`` cleanly.
    """

    def __init__(self, context: dict[str, Any], expression: str) -> None:
        self._context = context
        self._expression = expression

    # ---- dispatch ------------------------------------------------------- #

    def visit(self, node: ast.AST) -> Any:
        method = self._DISPATCH.get(type(node))
        if method is None:
            raise ConditionEvaluationError(
                f"Disallowed expression construct: {type(node).__name__}",
                expression=self._expression,
            )
        return method(self, node)

    # ---- atoms ---------------------------------------------------------- #

    def _visit_constant(self, node: ast.Constant) -> Any:
        # ``ast.Constant`` covers numeric / string / bool / None / bytes.
        # Reject bytes since we never want to compare against opaque blobs
        # in a routing decision (and it sidesteps any encoding surprises).
        if isinstance(node.value, bytes):
            raise ConditionEvaluationError(
                "Bytes literals are not allowed in conditions",
                expression=self._expression,
            )
        return node.value

    def _visit_name(self, node: ast.Name) -> Any:
        if node.id not in self._context:
            raise ConditionEvaluationError(
                f"Unknown variable {node.id!r} in condition",
                expression=self._expression,
            )
        return self._context[node.id]

    def _visit_list(self, node: ast.List) -> list[Any]:
        return [self.visit(elt) for elt in node.elts]

    def _visit_tuple(self, node: ast.Tuple) -> tuple[Any, ...]:
        return tuple(self.visit(elt) for elt in node.elts)

    # ---- access patterns ----------------------------------------------- #

    def _visit_subscript(self, node: ast.Subscript) -> Any:
        container = self.visit(node.value)
        # Only allow constant indices -- a computed/dynamic key has no
        # legitimate use in a routing condition and complicates reasoning
        # about what an expression can touch.
        index_node = node.slice
        if not isinstance(index_node, ast.Constant):
            raise ConditionEvaluationError(
                "Subscript index must be a literal constant",
                expression=self._expression,
            )
        key = index_node.value
        try:
            return container[key]
        except (KeyError, IndexError, TypeError) as exc:
            raise ConditionEvaluationError(
                f"Subscript {key!r} failed: {exc}",
                expression=self._expression,
            ) from exc

    def _visit_attribute(self, node: ast.Attribute) -> Any:
        # Block dunder access -- the canonical Python sandbox escape.
        # Even on an innocent-looking object, ``.__class__.__bases__[0]
        # .__subclasses__()`` walks to ``os._wrap_close`` and friends.
        if node.attr.startswith("_"):
            raise ConditionEvaluationError(
                f"Attribute access to private/dunder name {node.attr!r} is not allowed",
                expression=self._expression,
            )
        target = self.visit(node.value)
        # Pydantic models support attribute access naturally; dicts don't,
        # so fall back to dict-key lookup if the target is a Mapping. This
        # lets ``node['triage'].score`` work when ``node['triage']`` is a
        # dict (the flattened output map) without forcing the caller to
        # convert everything to attribute-bearing objects.
        if isinstance(target, dict):
            if node.attr in target:
                return target[node.attr]
            raise ConditionEvaluationError(
                f"Field {node.attr!r} not present on dict",
                expression=self._expression,
            )
        try:
            return getattr(target, node.attr)
        except AttributeError as exc:
            raise ConditionEvaluationError(
                f"Attribute {node.attr!r} not found: {exc}",
                expression=self._expression,
            ) from exc

    # ---- operators ------------------------------------------------------ #

    def _visit_compare(self, node: ast.Compare) -> bool:
        # Chained comparisons (``1 < x < 10``) are evaluated left-to-right
        # the same way Python evaluates them -- short-circuit on first
        # False. We use ast's left + comparators / ops parallel arrays.
        left = self.visit(node.left)
        for op, right_node in zip(node.ops, node.comparators):
            op_fn = _COMPARE_OPS.get(type(op))
            if op_fn is None:
                raise ConditionEvaluationError(
                    f"Unsupported comparison operator {type(op).__name__}",
                    expression=self._expression,
                )
            right = self.visit(right_node)
            try:
                result = op_fn(left, right)
            except TypeError as exc:
                raise ConditionEvaluationError(
                    f"Comparison failed: {exc}",
                    expression=self._expression,
                ) from exc
            if not result:
                return False
            left = right
        return True

    def _visit_boolop(self, node: ast.BoolOp) -> Any:
        # Short-circuit semantics matter here -- ``a or b`` should not
        # evaluate ``b`` if ``a`` is truthy, mirroring Python.
        if isinstance(node.op, ast.And):
            value: Any = True
            for sub in node.values:
                value = self.visit(sub)
                if not value:
                    return value
            return value
        if isinstance(node.op, ast.Or):
            value = False
            for sub in node.values:
                value = self.visit(sub)
                if value:
                    return value
            return value
        raise ConditionEvaluationError(
            f"Unsupported boolean operator {type(node.op).__name__}",
            expression=self._expression,
        )

    def _visit_unaryop(self, node: ast.UnaryOp) -> Any:
        op_fn = _UNARY_OPS.get(type(node.op))
        if op_fn is None:
            raise ConditionEvaluationError(
                f"Unsupported unary operator {type(node.op).__name__}",
                expression=self._expression,
            )
        operand = self.visit(node.operand)
        try:
            return op_fn(operand)
        except TypeError as exc:
            raise ConditionEvaluationError(
                f"Unary operator failed: {exc}",
                expression=self._expression,
            ) from exc

    def _visit_binop(self, node: ast.BinOp) -> Any:
        op_fn = _BIN_OPS.get(type(node.op))
        if op_fn is None:
            # Pow is the canonical case -- give it a specific message so
            # the playbook author isn't left wondering why ``**`` failed.
            if isinstance(node.op, ast.Pow):
                raise ConditionEvaluationError(
                    "Power operator (**) is not allowed in conditions "
                    "(potential CPU/memory exhaustion)",
                    expression=self._expression,
                )
            raise ConditionEvaluationError(
                f"Unsupported binary operator {type(node.op).__name__}",
                expression=self._expression,
            )
        left = self.visit(node.left)
        right = self.visit(node.right)
        try:
            return op_fn(left, right)
        except (TypeError, ZeroDivisionError) as exc:
            raise ConditionEvaluationError(
                f"Arithmetic failed: {exc}",
                expression=self._expression,
            ) from exc

    # ---- calls ---------------------------------------------------------- #

    def _visit_call(self, node: ast.Call) -> Any:
        # Only bare-name calls (``len(x)``); no method calls, no
        # attribute-style invocations. This is intentional -- letting
        # method calls through reintroduces the attribute-walk surface
        # we just blocked above.
        if not isinstance(node.func, ast.Name):
            raise ConditionEvaluationError(
                "Only direct function calls to allowlisted names are permitted",
                expression=self._expression,
            )
        name = node.func.id
        if name not in _ALLOWED_CALLABLES:
            raise ConditionEvaluationError(
                f"Function {name!r} is not in the allowlist "
                f"(allowed: {sorted(_ALLOWED_CALLABLES)})",
                expression=self._expression,
            )
        if node.keywords:
            raise ConditionEvaluationError(
                f"Keyword arguments are not allowed in calls to {name!r}",
                expression=self._expression,
            )
        args = [self.visit(a) for a in node.args]
        fn = _ALLOWED_CALLABLES[name]
        try:
            return fn(*args)
        except (TypeError, ValueError) as exc:
            raise ConditionEvaluationError(
                f"Call to {name!r} failed: {exc}",
                expression=self._expression,
            ) from exc

    # Built lazily so methods are bound; mypy/ruff prefer ClassVar but the
    # mapping must reference instance methods, so a plain class attribute
    # populated below is the simplest readable form.
    _DISPATCH: dict[type[ast.AST], Any] = {}


# Populate the dispatch table after the class body so each entry binds
# to the unbound method object the way ``visit`` expects.
_Evaluator._DISPATCH = {
    ast.Constant: _Evaluator._visit_constant,
    ast.Name: _Evaluator._visit_name,
    ast.List: _Evaluator._visit_list,
    ast.Tuple: _Evaluator._visit_tuple,
    ast.Subscript: _Evaluator._visit_subscript,
    ast.Attribute: _Evaluator._visit_attribute,
    ast.Compare: _Evaluator._visit_compare,
    ast.BoolOp: _Evaluator._visit_boolop,
    ast.UnaryOp: _Evaluator._visit_unaryop,
    ast.BinOp: _Evaluator._visit_binop,
    ast.Call: _Evaluator._visit_call,
}


# --------------------------------------------------------------------------- #
# Helpers used by the executor
# --------------------------------------------------------------------------- #


def coerce_to_branch(value: Any) -> str:
    """Coerce an evaluated condition value to the DecisionNode branch label.

    Mirrors :class:`DecisionNode.run`'s own coercion so the runner-side
    pre-evaluation produces the same ``"true"`` / ``"false"`` (for
    bools) / ``str(value)`` (for everything else) shape the Node would
    have produced if passed the raw ``value`` directly.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def build_condition_context(state_outputs: dict[str, Any]) -> dict[str, Any]:
    """Build the variable context handed to :func:`evaluate_condition`.

    Flattens :class:`WorkflowState.outputs` (a mapping of step_id ->
    BaseModel) into a ``node`` dict whose values are *also* dicts of
    that step's output fields. This lets a condition write either
    ``node['triage'].score`` (attribute-style on a model-shaped dict)
    or ``node['triage']['score']`` (subscript-style); the
    :class:`_Evaluator` handles both.

    The values are dicts rather than the raw BaseModel instances so we
    aren't exposing a live model object's attribute surface (and any
    private helpers it might carry) to the expression. Using the dump
    keeps the surface area to validated output fields only.
    """
    flat: dict[str, Any] = {}
    for step_id, output in state_outputs.items():
        # Output is typed (a BaseModel) for normal nodes, but the
        # passthrough nodes record a tiny wrapper -- ``model_dump``
        # works on both. Falling back to ``dict(output)`` covers the
        # paranoid case where a hand-built test bypasses the typed path.
        if hasattr(output, "model_dump"):
            flat[step_id] = output.model_dump()
        elif isinstance(output, dict):
            flat[step_id] = dict(output)
        else:
            flat[step_id] = output
    return {"node": flat}
