"""HITL gate step handler — block execution until human approval.

Uses LangGraph interrupt() for true human-in-the-loop integration.
Falls back to auto-approve in mock mode for testing.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from btagent_shared.types.playbook import HITLGateStep

logger = logging.getLogger("btagent.playbook.steps.hitl_gate")


async def execute_hitl_gate_step(
    step: HITLGateStep,
    context: dict[str, Any],
    *,
    mock: bool = True,
    interrupt_fn: Any = None,
) -> dict[str, Any]:
    """Execute a HITL gate step.

    In production, this calls LangGraph's ``interrupt()`` to pause the graph
    and wait for human input.  In mock mode, it auto-approves.

    Parameters
    ----------
    step : HITLGateStep
        The HITL gate step definition.
    context : dict
        Shared execution context.
    mock : bool
        If True, auto-approve without waiting for human input.
    interrupt_fn : callable | None
        LangGraph interrupt function. If provided and not mock, calls
        ``interrupt({"prompt": ..., "required_role": ...})`` to pause.

    Returns
    -------
    dict
        Step result with approval status.
    """
    started_at = datetime.now(UTC).isoformat()

    if mock:
        # Auto-approve in mock/dev mode
        logger.info(
            "HITL gate '%s' auto-approved (mock mode): %s",
            step.id,
            step.prompt,
        )
        return {
            "step_id": step.id,
            "status": "completed",
            "output": {
                "prompt": step.prompt,
                "required_role": step.required_role,
                "approved": True,
                "mock": True,
                "response": "Auto-approved in mock mode",
            },
            "started_at": started_at,
            "completed_at": datetime.now(UTC).isoformat(),
        }

    # Production path: use LangGraph interrupt
    if interrupt_fn is not None:
        logger.info(
            "HITL gate '%s' pausing for human approval: %s",
            step.id,
            step.prompt,
        )
        # This raises an interrupt that pauses the graph until
        # the human responds via the API.
        response = interrupt_fn(
            {
                "type": "hitl_gate",
                "step_id": step.id,
                "prompt": step.prompt,
                "required_role": step.required_role,
                "timeout_seconds": step.timeout_seconds,
            }
        )

        approved = response.get("approved", False) if isinstance(response, dict) else False
        status = "completed" if approved else "rejected"

        return {
            "step_id": step.id,
            "status": status,
            "output": {
                "prompt": step.prompt,
                "required_role": step.required_role,
                "approved": approved,
                "response": response,
            },
            "started_at": started_at,
            "completed_at": datetime.now(UTC).isoformat(),
        }

    # Fallback: no interrupt function, auto-reject for safety
    logger.warning(
        "HITL gate '%s' — no interrupt function available; auto-rejecting",
        step.id,
    )
    return {
        "step_id": step.id,
        "status": "rejected",
        "output": {
            "prompt": step.prompt,
            "required_role": step.required_role,
            "approved": False,
            "reason": "No interrupt function available",
        },
        "started_at": started_at,
        "completed_at": datetime.now(UTC).isoformat(),
    }
