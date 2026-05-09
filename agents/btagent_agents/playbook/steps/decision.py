"""Decision step handler — branch on a condition (safe, no eval).

Condition format: ``key.path OP value``
where OP is one of: >, <, >=, <=, ==, !=

Examples:
    "enrichment.max_confidence > 0.7"
    "alert.severity == critical"
    "iocs.count >= 5"
"""

from __future__ import annotations

import logging
import operator
import re
from datetime import UTC, datetime
from typing import Any

from btagent_shared.types.playbook import DecisionStep

logger = logging.getLogger("btagent.playbook.steps.decision")

# Supported comparison operators (no eval!)
_OPERATORS: dict[str, Any] = {
    ">": operator.gt,
    "<": operator.lt,
    ">=": operator.ge,
    "<=": operator.le,
    "==": operator.eq,
    "!=": operator.ne,
}

_CONDITION_RE = re.compile(r"^(?P<key>[\w.]+)\s*(?P<op>[><!]=?|==|!=)\s*(?P<value>.+)$")


def _resolve_key(data: dict[str, Any], key_path: str) -> Any:
    """Resolve a dotted key path against a nested dict.

    Example: ``"enrichment.max_confidence"`` resolves against
    ``{"enrichment": {"max_confidence": 0.9}}`` → ``0.9``.
    """
    parts = key_path.split(".")
    current: Any = data
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _coerce_value(raw: str) -> int | float | bool | str:
    """Attempt to coerce a string value to a numeric or boolean type."""
    raw = raw.strip().strip("'\"")

    if raw.lower() == "true":
        return True
    if raw.lower() == "false":
        return False

    try:
        return int(raw)
    except ValueError:
        pass

    try:
        return float(raw)
    except ValueError:
        pass

    return raw


def evaluate_condition(
    condition: str,
    context: dict[str, Any],
) -> bool:
    """Safely evaluate a condition string against a context dict.

    No eval() — uses regex parsing and operator dispatch.

    Parameters
    ----------
    condition : str
        Condition like ``"enrichment.max_confidence > 0.7"``.
    context : dict
        Execution context containing step outputs and trigger data.

    Returns
    -------
    bool
        True if condition is met, False otherwise.
    """
    match = _CONDITION_RE.match(condition.strip())
    if not match:
        logger.warning("Cannot parse condition: %r — defaulting to False", condition)
        return False

    key_path = match.group("key")
    op_str = match.group("op")
    raw_value = match.group("value")

    op_func = _OPERATORS.get(op_str)
    if op_func is None:
        logger.warning("Unknown operator '%s' in condition — defaulting to False", op_str)
        return False

    left = _resolve_key(context, key_path)
    right = _coerce_value(raw_value)

    if left is None:
        logger.info(
            "Key '%s' not found in context — condition evaluates to False",
            key_path,
        )
        return False

    # Coerce left side to match right type for comparison
    try:
        if isinstance(right, (int, float)) and not isinstance(right, bool):
            left = float(left)
        result = op_func(left, right)
        logger.info(
            "Condition '%s': %r %s %r → %s",
            condition,
            left,
            op_str,
            right,
            result,
        )
        return bool(result)
    except (TypeError, ValueError) as exc:
        logger.warning(
            "Condition evaluation failed for '%s': %s — defaulting to False",
            condition,
            exc,
        )
        return False


async def execute_decision_step(
    step: DecisionStep,
    context: dict[str, Any],
) -> dict[str, Any]:
    """Execute a decision step and return the chosen branch.

    Returns
    -------
    dict
        Step result with 'next_step' indicating which branch was chosen.
    """
    started_at = datetime.now(UTC).isoformat()

    result = evaluate_condition(step.condition, context)
    chosen_branch = step.true_branch if result else step.false_branch

    logger.info(
        "Decision step '%s': condition=%r → %s → branch=%s",
        step.id,
        step.condition,
        result,
        chosen_branch,
    )

    return {
        "step_id": step.id,
        "status": "completed",
        "output": {
            "condition": step.condition,
            "result": result,
            "chosen_branch": chosen_branch,
        },
        "next_step": chosen_branch,
        "started_at": started_at,
        "completed_at": datetime.now(UTC).isoformat(),
    }
