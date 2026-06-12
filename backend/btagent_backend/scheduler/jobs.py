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

from btagent_backend.config import get_settings
from btagent_backend.db.engine import async_session_factory
from btagent_backend.db.models import DEFAULT_ORG_ID
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


async def scheduled_hunt_pack_run(ctx: dict[str, Any]) -> dict[str, int]:
    """Run the enabled builtin hunt packs and land hits in the inbox (#112).

    The cron entry point for the Phase-6 integration slice: loads the enabled
    builtin packs, runs them through the engine runner against the configured
    backends, converts each :class:`SigmaHit` into a ``HuntFinding`` (so active
    suppressions apply pre-insert), and records a pack-run history row per pack.

    Org scope: v1 ingests into the **default org** — scheduled runs have no
    per-org pack store yet (see ``hunt_pack_run_service.DEFAULT_BUILTIN_PACKS``).

    Overlap guard: registered with arq's ``unique=True`` cron (a Redis lock on
    the scheduled instant), so a slow run can't be double-started by another
    worker firing the same cron tick. The thin shell here owns the single
    commit; the decision logic is in :mod:`hunt_pack_run_service`.
    """
    settings = get_settings()

    # Codex #202 P1: don't fire the scheduled run onto a backend whose live
    # path no-ops. ``hunt_schedule_enabled`` derives from ``mock_connectors``
    # (see config), so with mocks off in production this tick is a clear,
    # single warning rather than a silent zero-finding run. One log line per
    # tick keeps the cron from spamming while still surfacing the misconfig.
    if not settings.hunt_schedule_enabled:
        logger.warning(
            "hunt schedule disabled: live connectors not configured; "
            "set BTAGENT_HUNT_SCHEDULE_ENABLED=true to override"
        )
        return {"packs_run": 0, "findings_created": 0, "hits": 0, "failed_packs": 0}

    # Lazy import: the engine pulls pysigma, only present in the worker image.
    from btagent_backend.services import hunt_pack_run_service

    async with async_session_factory() as session:
        run_rows = await hunt_pack_run_service.run_pack_and_ingest(
            session,
            org_id=DEFAULT_ORG_ID,
            lookback_hours=settings.hunt_scheduler_lookback_hours,
            max_hits_per_query=settings.hunt_scheduler_max_hits_per_query,
        )
        await session.commit()

    counts = {
        "packs_run": len(run_rows),
        "findings_created": sum(r.findings_created for r in run_rows),
        "hits": sum(r.hit_count for r in run_rows),
        "failed_packs": sum(1 for r in run_rows if r.status == "failed"),
    }
    logger.info("scheduled_hunt_pack_run: %s", counts)
    return counts


async def run_hunt_pack(
    ctx: dict[str, Any],
    *,
    pack: dict[str, Any],
    schedule: dict[str, Any],
    org_id: str = DEFAULT_ORG_ID,
) -> dict[str, int]:
    """Compile + run one hunt pack and land its hits in the #119 store (#112).

    ``pack`` / ``schedule`` are serialised :class:`HuntPackManifest` /
    :class:`HuntSchedule`. The agents-side runner (which needs pysigma) is
    imported lazily so the backend's unit-test stack doesn't require it. In
    mock-connector mode a deterministic count-only executor is used; real
    MCP-backed count-only execution is the next increment.
    """
    # Lazy imports: pysigma + agents are only present in the worker image.
    from btagent_agents.plugins.hunter import (
        HuntPackRunner,
        SigmaCompiler,
        make_mock_hunt_executor,
    )
    from btagent_shared.hunt.huntpack import load_pack
    from btagent_shared.types.huntpack import HuntSchedule
    from btagent_shared.utils.ids import generate_id

    manifest = load_pack(pack)
    sched = HuntSchedule.model_validate(schedule)
    run_id = generate_id("hrun")

    executor = make_mock_hunt_executor() if get_settings().mock_connectors else _real_executor()
    runner = HuntPackRunner(SigmaCompiler(), executor)
    results = await runner.run_pack(manifest, sched, run_id=run_id)

    all_findings = [f for r in results for f in r.findings]
    async with async_session_factory() as session:
        await hunt_triage_service.persist_hunt_findings(
            session, org_id=org_id, findings=all_findings
        )
        await session.commit()

    counts = {
        "rules_executed": len(results),
        "findings_emitted": len(all_findings),
        "errored_rules": sum(1 for r in results if r.errors and not r.findings),
    }
    logger.info("run_hunt_pack %s: %s", manifest.id, counts)
    return counts


def _real_executor():
    """Placeholder for live MCP-backed count-only execution (#112 follow-up)."""
    raise NotImplementedError(
        "Live SIEM/EDR hunt execution is not yet wired; "
        "set BTAGENT_MOCK_CONNECTORS=true to use the deterministic executor."
    )
