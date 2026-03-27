"""Parallel fork step handler — fan-out to multiple branches concurrently."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from btagent_shared.types.playbook import ParallelForkStep

logger = logging.getLogger("btagent.playbook.steps.parallel")


async def execute_parallel_fork_step(
    step: ParallelForkStep,
    context: dict[str, Any],
    *,
    branch_executor: Any = None,
) -> dict[str, Any]:
    """Execute a parallel fork step, running all branches concurrently.

    Parameters
    ----------
    step : ParallelForkStep
        The parallel fork step definition containing branch lists.
    context : dict
        Shared execution context.
    branch_executor : callable | None
        Async callable that executes a list of step IDs sequentially.
        Signature: ``async def executor(step_ids: list[str], ctx: dict) -> dict``
        If None, returns mock results.

    Returns
    -------
    dict
        Step result with outputs from all branches.
    """
    started_at = datetime.now(timezone.utc).isoformat()

    if not step.branches:
        logger.info("Parallel fork '%s' has no branches — skipping", step.id)
        return {
            "step_id": step.id,
            "status": "completed",
            "output": {"branches": [], "results": []},
            "started_at": started_at,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }

    if branch_executor is None:
        # Mock mode: simulate branch execution
        branch_results = []
        for i, branch in enumerate(step.branches):
            branch_results.append({
                "branch_index": i,
                "step_ids": branch,
                "status": "completed",
                "mock": True,
            })

        logger.info(
            "Parallel fork '%s' mock-executed %d branches",
            step.id,
            len(step.branches),
        )
        return {
            "step_id": step.id,
            "status": "completed",
            "output": {
                "branches": step.branches,
                "results": branch_results,
            },
            "started_at": started_at,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }

    # Production: run all branches concurrently
    async def _run_branch(index: int, step_ids: list[str]) -> dict[str, Any]:
        try:
            result = await branch_executor(step_ids, context)
            return {
                "branch_index": index,
                "step_ids": step_ids,
                "status": "completed",
                "result": result,
            }
        except Exception as exc:
            logger.error(
                "Parallel fork '%s' branch %d failed: %s",
                step.id,
                index,
                exc,
            )
            return {
                "branch_index": index,
                "step_ids": step_ids,
                "status": "failed",
                "error": str(exc),
            }

    tasks = [
        _run_branch(i, branch)
        for i, branch in enumerate(step.branches)
    ]
    branch_results = await asyncio.gather(*tasks)

    all_ok = all(r["status"] == "completed" for r in branch_results)
    status = "completed" if all_ok else "partially_failed"

    logger.info(
        "Parallel fork '%s' completed: %d/%d branches succeeded",
        step.id,
        sum(1 for r in branch_results if r["status"] == "completed"),
        len(branch_results),
    )

    return {
        "step_id": step.id,
        "status": status,
        "output": {
            "branches": step.branches,
            "results": list(branch_results),
        },
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
