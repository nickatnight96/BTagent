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
from btagent_backend.scheduler.jobs import (
    behavioral_baseline_sweep,
    compile_proposal_plan,
    execute_hunt_plan,
    run_hunt_pack,
    scheduled_deception_hunt_scan,
    scheduled_email_hunt_scan,
    scheduled_hunt_pack_run,
    stale_suppression_sweep,
    validate_detection_proposal,
    weekly_pattern_scan,
)

logger = logging.getLogger("btagent.scheduler.worker")


def redis_settings() -> RedisSettings:
    """Build arq RedisSettings from the app's ``BTAGENT_REDIS_URL``.

    Public: the pattern-hunt accept route uses this to enqueue the
    ``compile_proposal_plan`` job on the live-LLM path.
    """
    return RedisSettings.from_dsn(get_settings().redis_url)


def _hunt_pack_cron_hours() -> set[int]:
    """Hours-of-day the scheduled hunt-pack cron fires on.

    arq crons are wall-clock, not interval, so an "every N hours" cadence is
    expressed as the set of hours ``{0, N, 2N, ...}``. Derived from
    ``BTAGENT_HUNT_SCHEDULER_INTERVAL_HOURS`` (default 4 → 00:00, 04:00,
    08:00, …). An interval ≤0 or >24 clamps to a single daily run.
    """
    interval = get_settings().hunt_scheduler_interval_hours
    if interval <= 0 or interval > 24:
        return {0}
    return set(range(0, 24, interval))


def _behavioral_cron_hours() -> set[int]:
    """Hours-of-day the behavioral baseline+stale sweep cron fires on.

    Same wall-clock cadence expansion as :func:`_hunt_pack_cron_hours`, driven
    by ``BTAGENT_BEHAVIORAL_SCHEDULER_INTERVAL_HOURS`` (default 6 → 00:00,
    06:00, 12:00, 18:00). An interval ≤0 or >24 clamps to a single daily run.
    """
    interval = get_settings().behavioral_scheduler_interval_hours
    if interval <= 0 or interval > 24:
        return {0}
    return set(range(0, 24, interval))


def _email_hunt_cron_hours() -> set[int]:
    """Hours-of-day the scheduled email-hunt cron fires on.

    Same wall-clock cadence expansion as :func:`_hunt_pack_cron_hours`, driven
    by ``BTAGENT_EMAIL_HUNT_SCAN_INTERVAL_HOURS`` (default 6 → 00:00, 06:00,
    12:00, 18:00). An interval ≤0 or >24 clamps to a single daily run.
    """
    interval = get_settings().email_hunt_scan_interval_hours
    if interval <= 0 or interval > 24:
        return {0}
    return set(range(0, 24, interval))


def _deception_hunt_cron_hours() -> set[int]:
    """Hours-of-day the scheduled deception-hunt cron fires on.

    Same wall-clock cadence expansion as :func:`_hunt_pack_cron_hours`, driven
    by ``BTAGENT_DECEPTION_HUNT_SCAN_INTERVAL_HOURS`` (default 6 → 00:00, 06:00,
    12:00, 18:00). An interval ≤0 or >24 clamps to a single daily run.
    """
    interval = get_settings().deception_hunt_scan_interval_hours
    if interval <= 0 or interval > 24:
        return {0}
    return set(range(0, 24, interval))


async def _on_startup(ctx: dict) -> None:
    logger.info("BTagent scheduler worker started")


async def _on_shutdown(ctx: dict) -> None:
    logger.info("BTagent scheduler worker stopping")


class WorkerSettings:
    """arq worker configuration.

    ``functions`` exposes jobs for ad-hoc enqueue; ``cron_jobs`` are the
    recurring ones. The stale-suppression sweep runs hourly — frequent
    enough that a flipped rule surfaces for re-confirmation the same day,
    cheap enough to be inconsequential. The scheduled hunt-pack run fires
    on the configured cadence (default every 4h) and lands its hits in the
    #119 triage inbox.

    Both crons use arq's ``unique=True`` (the default): arq takes a Redis
    lock keyed on each cron's scheduled instant, so even with multiple
    worker replicas a given tick runs exactly once — the overlap/idempotency
    guard for the hunt-pack run.
    """

    # ``run_hunt_pack`` is enqueue-on-demand (a pack + schedule payload);
    # ``scheduled_hunt_pack_run`` is the cron that runs the enabled builtin
    # packs against the configured backends and ingests into the inbox.
    functions = [
        stale_suppression_sweep,
        run_hunt_pack,
        scheduled_hunt_pack_run,
        scheduled_email_hunt_scan,
        scheduled_deception_hunt_scan,
        weekly_pattern_scan,
        behavioral_baseline_sweep,
        # #120 Phase C: enqueue-on-demand from the proposal accept / execute
        # routes (live paths; mock mode runs inline in the route).
        compile_proposal_plan,
        execute_hunt_plan,
        # #113 slice 2: enqueue-on-demand from the CTI validate route.
        validate_detection_proposal,
    ]
    cron_jobs = [
        cron(
            stale_suppression_sweep,
            minute=get_settings().hunt_suppression_sweep_minute,
            unique=True,
        ),
        cron(
            scheduled_hunt_pack_run,
            hour=_hunt_pack_cron_hours(),
            minute=0,
            unique=True,
        ),
        # Email-hunt vertical: gather the email connectors + land phishing
        # findings on a wall-clock cadence. Gated on ``email_hunt_schedule_
        # enabled`` (derives from mocks) inside the job; ``unique=True`` so a
        # tick runs exactly once across worker replicas.
        cron(
            scheduled_email_hunt_scan,
            hour=_email_hunt_cron_hours(),
            minute=0,
            unique=True,
        ),
        # Deception-hunt vertical: gather the Canary connector + land the
        # fleet's highest-fidelity findings on a wall-clock cadence. Gated on
        # ``deception_hunt_schedule_enabled`` (derives from mocks) inside the
        # job; ``unique=True`` so a tick runs exactly once across replicas.
        cron(
            scheduled_deception_hunt_scan,
            hour=_deception_hunt_cron_hours(),
            minute=0,
            unique=True,
        ),
        # #120: weekly cross-investigation pattern scan. Wall-clock weekly via
        # (weekday, hour, minute). Not connector-blocked — runs over the
        # already-stored closed-investigation corpus.
        cron(
            weekly_pattern_scan,
            weekday=get_settings().pattern_scan_weekday,
            hour=get_settings().pattern_scan_hour,
            minute=0,
            unique=True,
        ),
        # Behavioral Hunter maintenance (#114): baseline rebuild (gated on a
        # wired telemetry feed) + stale-entity sweep. ``unique=True`` so a
        # given tick runs exactly once across worker replicas.
        cron(
            behavioral_baseline_sweep,
            hour=_behavioral_cron_hours(),
            minute=0,
            unique=True,
        ),
    ]
    on_startup = _on_startup
    on_shutdown = _on_shutdown
    redis_settings = redis_settings()
