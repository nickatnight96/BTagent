"""Background job functions for the arq worker.

Each job is a thin, side-effectful shell: open a DB session, delegate to a
service, commit. The decision logic lives in the services / pure-logic
cores so the jobs themselves need no dedicated unit tests beyond a wiring
check (the service functions are tested directly).

arq calls each job with a ``ctx`` dict as the first arg; we don't use it
yet (no per-job Redis state), but keep the signature so jobs can later read
``ctx["redis"]`` / ``ctx["job_id"]``.
"""

from __future__ import annotations

import logging
from typing import Any

from btagent_backend.db.engine import async_session_factory
from btagent_backend.services import hunt_triage_service

logger = logging.getLogger("btagent.scheduler.jobs")


async def stale_suppression_sweep(ctx: dict[str, Any]) -> dict[str, int]:
    """Flip expired / due-for-reconfirmation suppression rules (#119).

    Runs on a cron (see :mod:`btagent_backend.scheduler.worker`). Returns the
    sweep counts so they show up in arq's job result + our logs.
    """
    async with async_session_factory() as session:
        result = await hunt_triage_service.sweep_stale_suppressions(session)
        await session.commit()
    logger.info(
        "stale_suppression_sweep: scanned=%d expired=%d needs_reconfirm=%d",
        result.get("scanned", 0),
        result.get("expired", 0),
        result.get("needs_reconfirm", 0),
    )
    return result
