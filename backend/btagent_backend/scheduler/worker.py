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
    behavioral_benign_reeval_sweep,
    compile_proposal_plan,
    execute_hunt_plan,
    execute_workflow_run,
    memory_consolidation_sweep,
    noise_digest_sweep,
    run_hunt_pack,
    scheduled_deception_hunt_scan,
    scheduled_email_hunt_scan,
    scheduled_hunt_pack_run,
    scheduled_ndr_hunt_scan,
    shift_handover_digest,
    stale_suppression_sweep,
    taxii_feed_poll_sweep,
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


def _ndr_hunt_cron_hours() -> set[int]:
    """Hours-of-day the scheduled NDR-hunt cron fires on.

    Same wall-clock cadence expansion as :func:`_hunt_pack_cron_hours`, driven
    by ``BTAGENT_NDR_HUNT_SCAN_INTERVAL_HOURS`` (default 6 → 00:00, 06:00,
    12:00, 18:00). An interval ≤0 or >24 clamps to a single daily run.
    """
    interval = get_settings().ndr_hunt_scan_interval_hours
    if interval <= 0 or interval > 24:
        return {0}
    return set(range(0, 24, interval))


def _taxii_poll_cron_minutes() -> set[int]:
    """Minutes-past-the-hour the TAXII feed-poll sweep fires on (#105).

    arq crons are wall-clock, so an "every N minutes" cadence is the set
    ``{0, N, 2N, ...}`` within the hour. Derived from
    ``BTAGENT_TAXII_POLL_SWEEP_INTERVAL_MINUTES`` (default 15 → :00, :15, :30,
    :45). An interval ≤0 or >60 clamps to once an hour. The sweep itself is
    cheap when nothing is due — it only polls feeds whose own
    ``poll_interval_minutes`` has elapsed.
    """
    interval = get_settings().taxii_poll_sweep_interval_minutes
    if interval <= 0 or interval > 60:
        return {0}
    return set(range(0, 60, interval))


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
        noise_digest_sweep,
        run_hunt_pack,
        scheduled_hunt_pack_run,
        scheduled_email_hunt_scan,
        scheduled_deception_hunt_scan,
        scheduled_ndr_hunt_scan,
        weekly_pattern_scan,
        behavioral_baseline_sweep,
        behavioral_benign_reeval_sweep,
        memory_consolidation_sweep,
        # #105 UC-2.1: poll every org's due TAXII 2.1 feeds and ingest their
        # objects through the existing STIX ingest path.
        taxii_feed_poll_sweep,
        # #120 Phase C: enqueue-on-demand from the proposal accept / execute
        # routes (live paths; mock mode runs inline in the route).
        compile_proposal_plan,
        execute_hunt_plan,
        # #113 slice 2: enqueue-on-demand from the CTI validate route.
        validate_detection_proposal,
        # Background workflow execution: enqueue-on-demand from the run route.
        execute_workflow_run,
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
        # NDR-hunt vertical: gather the Vectra connector + land per-host
        # kill-chain campaign findings on a wall-clock cadence. Gated on
        # ``ndr_hunt_schedule_enabled`` (derives from mocks) inside the job;
        # ``unique=True`` so a tick runs exactly once across replicas.
        cron(
            scheduled_ndr_hunt_scan,
            hour=_ndr_hunt_cron_hours(),
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
        # Behavioral Hunter benign-label re-evaluation (#114 Phase B): nightly
        # re-check of historical benign verdicts against the current baselines,
        # flagging entities whose "already cleared" patterns have drifted out of
        # normal. Runs over already-stored rows (not connector-blocked) at 03:50
        # UTC — after the memory consolidation pass and before the 06:30 noise
        # digest, and off the baseline-sweep hours so a rebuild isn't half-done
        # underneath it. ``unique=True`` — one tick across worker replicas.
        cron(
            behavioral_benign_reeval_sweep,
            hour=3,
            minute=50,
            unique=True,
        ),
        # #112 newly-noisy digest: daily diff of the noise baseline against
        # the per-org digest state; notifies hunt seniors about NEW chronic
        # rules only. Fixed daily cadence (06:30 UTC — after the overnight
        # pack-run crons so the diff sees fresh rule_stats).
        cron(
            noise_digest_sweep,
            hour=6,
            minute=30,
            unique=True,
        ),
        # #108 UC-5.1 shift-handover digest: at each 8h shift boundary, push
        # every org's handover headline to analysts' bells (quiet windows stay
        # silent inside the producer). ``unique=True`` — one tick per boundary
        # across worker replicas.
        # #482: nightly agent-memory consolidation. Not connector-blocked —
        # it runs over the already-stored memory rows. Fires at 03:20 UTC, in
        # the quiet window between the overnight hunt crons and the 06:30
        # noise digest. ``unique=True`` — one tick across worker replicas.
        cron(
            memory_consolidation_sweep,
            hour=3,
            minute=20,
            unique=True,
        ),
        cron(
            shift_handover_digest,
            hour={6, 14, 22},
            minute=0,
            unique=True,
        ),
        # #105 UC-2.1: TAXII feed poll sweep. Fires on the configured
        # minute cadence (default every 15 min); the per-feed
        # ``poll_interval_minutes`` decides which feeds actually poll on a
        # given tick. ``unique=True`` so a tick runs exactly once across
        # worker replicas — two replicas polling the same feed concurrently
        # would double-ingest and race the cursor.
        cron(
            taxii_feed_poll_sweep,
            minute=_taxii_poll_cron_minutes(),
            unique=True,
        ),
    ]
    on_startup = _on_startup
    on_shutdown = _on_shutdown
    redis_settings = redis_settings()

    #: How often the worker stamps its health key in Redis.
    #:
    #: arq defaults this to **3600s**, which makes the key useless as a
    #: liveness signal: it is written with a TTL of ``interval + 1``, so a
    #: worker that wedged five minutes ago still looks healthy for another
    #: fifty-five. 30s means a wedge is visible within about half a minute.
    #:
    #: The chart's scheduler ``livenessProbe`` runs ``arq --check`` against
    #: this key, so the two are coupled: the probe's
    #: ``periodSeconds x failureThreshold`` must stay comfortably larger than
    #: this interval, or a single slow heartbeat restarts a healthy worker.
    #: ``test_scheduler_liveness.py`` pins that relationship.
    #:
    #: Cost is one small Redis SET per interval — the heartbeat loop this
    #: rides on already runs every second.
    health_check_interval = 30
