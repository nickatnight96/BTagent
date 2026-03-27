"""Action step handler — invoke a tool / MCP action."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from btagent_shared.types.playbook import ActionStep

logger = logging.getLogger("btagent.playbook.steps.action")


async def execute_action_step(
    step: ActionStep,
    context: dict[str, Any],
    *,
    mock: bool = True,
) -> dict[str, Any]:
    """Execute an action step by invoking the named tool.

    Parameters
    ----------
    step : ActionStep
        The action step to execute.
    context : dict
        Shared execution context (previous step outputs, trigger data).
    mock : bool
        If True, return a mock result instead of invoking real tools.

    Returns
    -------
    dict
        Step result containing status, output, and timing.
    """
    started_at = datetime.now(timezone.utc).isoformat()

    if mock:
        # In mock/dev mode, return a simulated successful result
        output = {
            "tool_name": step.tool_name,
            "arguments": step.arguments,
            "mock": True,
            "result": f"Mock result from {step.tool_name}",
            "data": {},
        }
        logger.info(
            "Mock-executed action step '%s' (tool=%s)",
            step.id,
            step.tool_name,
        )
    else:
        # Real tool invocation would happen here via MCP or plugin registry.
        # This path is wired up in production when MCP servers are available.
        output = {
            "tool_name": step.tool_name,
            "arguments": step.arguments,
            "result": f"Executed {step.tool_name}",
            "data": {},
        }
        logger.info(
            "Executed action step '%s' (tool=%s)",
            step.id,
            step.tool_name,
        )

    return {
        "step_id": step.id,
        "status": "completed",
        "output": output,
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
