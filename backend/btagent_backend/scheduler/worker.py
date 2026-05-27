"""arq worker entrypoint and cron registration.

Run with::

    arq btagent_backend.scheduler.worker.WorkerSettings

The worker shares the backend image; in compose/Helm it's a separate
process role so hunt scheduling doesn't compete with API request handling.
Redis is the broker (already a hard dependency of the stack).
"""

from __future__ import annotations

import logging

from arq import cron
from arq.connections import RedisSettings

from btagent_backend.config import get_settings
from btagent_backend.scheduler.jobs import run_hunt_pack, stale_suppression_sweep

logger = logging.getLogger("btagent.scheduler.worker")


def _redis_settings() -> RedisSettings:
    """Build arq RedisSettings from the app's ``BTAGENT_REDIS_URL``."""
    return RedisSettings.from_dsn(get_settings().redis_url)


async def _on_startup(ctx: dict) -> None:
    logger.info("BTagent scheduler worker started")


async def _on_shutdown(ctx: dict) -> None:
    logger.info("BTagent scheduler worker stopping")


class WorkerSettings:
    """arq worker configuration.

    ``functions`` exposes jobs for ad-hoc enqueue; ``cron_jobs`` are the
    recurring ones. The stale-suppression sweep runs hourly — frequent
    enough that a flipped rule surfaces for re-confirmation the same day,
    cheap enough to be inconsequential.
    """

    # ``run_hunt_pack`` is enqueue-on-demand (a pack + schedule payload).
    # Cron-style scheduled discovery from a pack store lands with the pack
    # persistence layer in a follow-up; for now packs are triggered explicitly.
    functions = [stale_suppression_sweep, run_hunt_pack]
    cron_jobs = [
        cron(stale_suppression_sweep, minute=0),  # top of every hour
    ]
    on_startup = _on_startup
    on_shutdown = _on_shutdown
    redis_settings = _redis_settings()
