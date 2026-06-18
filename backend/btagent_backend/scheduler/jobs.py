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


async def weekly_pattern_scan(ctx: dict[str, Any]) -> dict[str, int]:
    """Surface cross-investigation weak-signal patterns as hunt proposals (#120).

    The weekly cron entry point for the Cross-Investigation Pattern Hunter.
    Walks the **closed-investigation pgvector corpus** (no live connectors —
    this hunt is not connector-blocked), extracts weak signals, ranks clusters
    by ``frequency × recency × cross-investigation diversity`` (diversity
    dominant), and upserts the top-N as ``pattern_hunt_proposals``.

    Multi-tenant: ``scan_corpus`` and the weak-signal / proposal tables are all
    org-scoped, so the job scans **every** organization — running it against a
    single hard-coded ``DEFAULT_ORG_ID`` would permanently exclude every other
    tenant's corpus. One ``scan_corpus`` call per org, counts aggregated.

    Thin shell: the single commit lives here (after all orgs are scanned); all
    decisions are in :mod:`btagent_backend.services.pattern_hunt_service` /
    :mod:`btagent_shared.hunt.pattern`. Gated behind ``pattern_scan_enabled``
    (mirrors ``hunt_schedule_enabled`` in shape but defaults on, since there is
    nothing to no-op against — the corpus is already stored).
    """
    settings = get_settings()
    if not settings.pattern_scan_enabled:
        logger.warning("pattern scan disabled: set BTAGENT_PATTERN_SCAN_ENABLED=true to enable")
        return {
            "orgs_scanned": 0,
            "investigations_scanned": 0,
            "weak_signals_upserted": 0,
            "clusters_ranked": 0,
            "proposals_created": 0,
            "proposals_updated": 0,
        }

    from btagent_backend.services import pattern_hunt_service

    async with async_session_factory() as session:
        result = await pattern_hunt_service.scan_all_orgs(
            session,
            top_n=settings.pattern_scan_top_n,
        )
        await session.commit()

    counts = {
        "orgs_scanned": result.orgs_scanned,
        "investigations_scanned": result.investigations_scanned,
        "weak_signals_upserted": result.weak_signals_upserted,
        "clusters_ranked": result.clusters_ranked,
        "proposals_created": result.proposals_created,
        "proposals_updated": result.proposals_updated,
    }
    logger.info("weekly_pattern_scan: %s", counts)
    return counts


async def behavioral_baseline_sweep(ctx: dict[str, Any]) -> dict[str, int]:
    """Behavioral Hunter maintenance cron: stale-sweep (+ baseline-build) (#114).

    Mirrors :func:`stale_suppression_sweep` / :func:`scheduled_hunt_pack_run`:
    a thin shell that opens a session, delegates to ``behavioral_service``, and
    commits once. Two halves:

    * **Stale-entity archival** — always runs. Entities unseen for
      ``behavioral_stale_after_days`` are candidates for archival so the active
      baseline pool doesn't accumulate noise from departed users /
      decommissioned hosts. The list is logged here; the destructive archival
      action (and the per-entity ``BehavioralEntityRow`` lifecycle column) is a
      Phase B follow-up — surfacing the count is the Phase A slice.
    * **Baseline rebuild** — gated. There is NO live EDR telemetry feed wired
      yet, so there is no event source to fold into fresh baselines. Rather
      than fabricate data, the baseline-build half is skipped with a single
      clear "no telemetry source wired" warning whenever
      ``behavioral_schedule_enabled`` is false (the default with mocks off).
      An operator who wires a telemetry source sets
      ``BTAGENT_BEHAVIORAL_SCHEDULE_ENABLED=true`` to flip this on; the actual
      ingest+build wiring lands with that feed.

    Returns the sweep counts so they show up in arq's job result + our logs.
    """
    settings = get_settings()
    from datetime import timedelta

    from btagent_backend.services import behavioral_service

    async with async_session_factory() as session:
        stale = await behavioral_service.stale_entities(
            session,
            stale_after=timedelta(days=settings.behavioral_stale_after_days),
        )
        # Read-only sweep in the Phase A slice — nothing to commit yet, but the
        # session is committed for symmetry with the other jobs (and so a future
        # archival mutation needs no shell change).
        await session.commit()

    if not settings.behavioral_schedule_enabled:
        # No live EDR telemetry feed is wired, so there is no event source to
        # build fresh baselines from. One warning per tick (not per entity)
        # surfaces the misconfig without spamming the log.
        logger.warning(
            "behavioral baseline-build skipped: no telemetry source wired; "
            "set BTAGENT_BEHAVIORAL_SCHEDULE_ENABLED=true once an EDR feed is "
            "configured to enable the baseline rebuild half of this sweep"
        )

    counts = {"stale_entities": len(stale), "baselines_built": 0}
    logger.info("behavioral_baseline_sweep: %s", counts)
    return counts
