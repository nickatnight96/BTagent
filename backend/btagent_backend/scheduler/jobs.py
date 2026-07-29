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
from datetime import UTC, datetime, timedelta
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


async def memory_consolidation_sweep(ctx: dict[str, Any]) -> dict[str, int]:
    """Collapse near-duplicate long-term agent memories, org by org (#482).

    The nightly cron for the unified memory store's consolidation pass. For
    every org that has memories, groups the live rows by ``(subject,
    tlp_level)``, collapses each cluster of near-duplicate content onto its
    highest-confidence/most-recent survivor, and stamps the losers
    ``superseded_at`` so they drop out of every recall path (the rows are kept
    for audit, not deleted).

    Multi-tenant and best-effort, mirroring :func:`weekly_pattern_scan`: the
    service walks **every** org (a single hard-coded ``DEFAULT_ORG_ID`` sweep
    would permanently exclude every other tenant), and a failure on one org is
    logged and skipped rather than aborting the tick. Consolidation never
    merges across TLP levels — see ``memory_service.consolidate_memories``.

    Thin shell: the single commit lives here; all decisions are in
    :mod:`btagent_backend.services.memory_service`.
    """
    from btagent_backend.services import memory_service

    async with async_session_factory() as session:
        result = await memory_service.consolidate_all_orgs(session)
        await session.commit()

    counts = result.as_counts()
    logger.info("memory_consolidation_sweep: %s", counts)
    return counts


async def taxii_feed_poll_sweep(ctx: dict[str, Any]) -> dict[str, int]:
    """Poll every org's due TAXII 2.1 feeds and ingest their objects (#105).

    The cron entry point for the pull half of UC-2.1 "STIX/TAXII feeds". For
    each **enabled** feed whose own ``poll_interval_minutes`` has elapsed, the
    service polls the collection since that feed's stored cursor, ingests the
    returned STIX objects through the *existing* ``stix_service`` path (so TLP
    is derived from each object's markings exactly as the bundle import does),
    advances the cursor, and stamps the poll telemetry.

    Multi-tenant, mirroring :func:`weekly_pattern_scan` /
    :func:`memory_consolidation_sweep`: the service walks **every** org's feeds
    — a single hard-coded ``DEFAULT_ORG_ID`` sweep would permanently exclude
    every other tenant.

    Best-effort per feed: a feed that raises is recorded on its own row
    (``last_status='error'`` plus a scrubbed ``last_error``) and the sweep
    continues, so one unreachable server cannot sink the tick.

    Gate: ``taxii_poll_enabled``. Unlike the hunt schedulers this does not
    derive from ``mock_connectors`` — the TAXII client's live path is fully
    implemented, and the sweep is inert by construction when no feeds exist.

    Thin shell: the single commit lives here; all decisions are in
    :mod:`btagent_backend.services.taxii_poll_service`.
    """
    settings = get_settings()
    if not settings.taxii_poll_enabled:
        logger.warning("TAXII feed polling disabled: set BTAGENT_TAXII_POLL_ENABLED=true to enable")
        return {
            "feeds_considered": 0,
            "feeds_polled": 0,
            "feeds_skipped": 0,
            "feeds_failed": 0,
            "objects_fetched": 0,
            "iocs_created": 0,
        }

    from btagent_backend.services import taxii_poll_service

    async with async_session_factory() as session:
        result = await taxii_poll_service.poll_due_feeds(
            session, max_objects=settings.taxii_max_objects_per_poll
        )
        await session.commit()

    counts = result.as_counts()
    logger.info("taxii_feed_poll_sweep: %s", counts)
    return counts


async def scheduled_hunt_pack_run(ctx: dict[str, Any]) -> dict[str, int]:
    """Run the enabled builtin hunt packs and land hits in the inbox (#112).

    The cron entry point for the Phase-6 integration slice: loads the packs the
    org has **enabled** in the per-org pack store, runs them through the engine
    runner against the configured backends, converts each :class:`SigmaHit`
    into a ``HuntFinding`` (so active suppressions apply pre-insert), and
    records a pack-run history row per pack.

    Org scope: the cron still sweeps the **default org**; which packs it runs
    for that org now comes from ``org_hunt_packs`` via
    :func:`hunt_pack_store.enabled_pack_names`, falling back to
    ``hunt_pack_store.DEFAULT_BUILTIN_PACKS`` when the org has no rows.

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


async def scheduled_email_hunt_scan(ctx: dict[str, Any]) -> dict[str, int]:
    """Run an email hunt over the email connectors and land findings (email vertical).

    The cron entry point that gives the email-hunt vertical a hands-free
    cadence: gathers Defender for O365 / Proofpoint / Mimecast telemetry over
    the configured lookback window, correlates it into phishing incidents, maps
    those into ``email``-domain findings, and persists them (clustered +
    suppression-checked on insert). Mirrors :func:`scheduled_hunt_pack_run`.

    Gate: ``email_hunt_schedule_enabled`` derives from ``mock_connectors`` — the
    email connectors are mock-first, so with mocks off the live gather refuses
    per-tool and would land zero findings. One warning per tick surfaces the
    misconfig rather than spamming. Org scope: v1 ingests into the default org.
    The thin shell owns the single commit; the logic is in
    :mod:`email_hunt_run_service`.
    """
    settings = get_settings()

    if not settings.email_hunt_schedule_enabled:
        logger.warning(
            "email hunt schedule disabled: live email connectors not configured; "
            "set BTAGENT_EMAIL_HUNT_SCHEDULE_ENABLED=true to override"
        )
        return {"total_incidents": 0, "findings_created": 0, "findings_emitted": 0}

    from btagent_backend.services import email_hunt_run_service

    now = datetime.now(UTC)
    start = (now - timedelta(hours=settings.email_hunt_lookback_hours)).isoformat()
    end = now.isoformat()

    async with async_session_factory() as session:
        summary = await email_hunt_run_service.run_email_hunt_and_ingest(
            session, org_id=DEFAULT_ORG_ID, start=start, end=end
        )
        await session.commit()

    counts = {
        "total_incidents": int(summary["total_incidents"]),
        "findings_created": int(summary["findings_created"]),
        "findings_emitted": int(summary["findings_emitted"]),
    }
    logger.info("scheduled_email_hunt_scan: %s", counts)
    return counts


async def scheduled_deception_hunt_scan(ctx: dict[str, Any]) -> dict[str, int]:
    """Run a deception hunt over the Canary connector and land findings.

    The cron entry point that gives the deception-hunt vertical a hands-free
    cadence: gathers Thinkst Canary incidents, correlates them into ranked
    deception incidents, maps those into ``deception``-domain findings, and
    persists them (clustered + suppression-checked on insert). Mirrors
    :func:`scheduled_email_hunt_scan` but has no lookback window — the Canary
    connector exposes no time filter.

    Gate: ``deception_hunt_schedule_enabled`` derives from ``mock_connectors``
    — the Canary connector is mock-first, so with mocks off the live gather
    refuses and would land zero findings. One warning per tick surfaces the
    misconfig rather than spamming. Org scope: v1 ingests into the default org.
    The thin shell owns the single commit; the logic is in
    :mod:`deception_hunt_run_service`.
    """
    settings = get_settings()

    if not settings.deception_hunt_schedule_enabled:
        logger.warning(
            "deception hunt schedule disabled: live Canary connector not configured; "
            "set BTAGENT_DECEPTION_HUNT_SCHEDULE_ENABLED=true to override"
        )
        return {"total_incidents": 0, "findings_created": 0, "findings_emitted": 0}

    from btagent_backend.services import deception_hunt_run_service

    async with async_session_factory() as session:
        summary = await deception_hunt_run_service.run_deception_hunt_and_ingest(
            session, org_id=DEFAULT_ORG_ID
        )
        await session.commit()

    counts = {
        "total_incidents": int(summary["total_incidents"]),
        "findings_created": int(summary["findings_created"]),
        "findings_emitted": int(summary["findings_emitted"]),
    }
    logger.info("scheduled_deception_hunt_scan: %s", counts)
    return counts


async def scheduled_ndr_hunt_scan(ctx: dict[str, Any]) -> dict[str, int]:
    """Run an NDR hunt over the Vectra connector and land findings.

    The cron entry point that gives the NDR-hunt vertical a hands-free cadence:
    gathers Vectra network detections, correlates them into ranked per-host
    kill-chain campaign rollups, maps those into ``ndr``-domain findings, and
    persists them (clustered + suppression-checked on insert). Mirrors
    :func:`scheduled_deception_hunt_scan` — no lookback window (the Vectra
    connector exposes no time filter).

    Gate: ``ndr_hunt_schedule_enabled`` derives from ``mock_connectors`` — the
    Vectra connector is mock-first, so with mocks off the live gather refuses
    and would land zero findings. One warning per tick surfaces the misconfig
    rather than spamming. Org scope: v1 ingests into the default org. The thin
    shell owns the single commit; the logic is in :mod:`ndr_hunt_run_service`.
    """
    settings = get_settings()

    if not settings.ndr_hunt_schedule_enabled:
        logger.warning(
            "ndr hunt schedule disabled: live Vectra connector not configured; "
            "set BTAGENT_NDR_HUNT_SCHEDULE_ENABLED=true to override"
        )
        return {"total_hosts": 0, "findings_created": 0, "findings_emitted": 0}

    from btagent_backend.services import ndr_hunt_run_service

    async with async_session_factory() as session:
        summary = await ndr_hunt_run_service.run_ndr_hunt_and_ingest(session, org_id=DEFAULT_ORG_ID)
        await session.commit()

    counts = {
        "total_hosts": int(summary["total_hosts"]),
        "findings_created": int(summary["findings_created"]),
        "findings_emitted": int(summary["findings_emitted"]),
    }
    logger.info("scheduled_ndr_hunt_scan: %s", counts)
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
      ``behavioral_stale_after_days`` are stamped ``archived_at`` so the active
      baseline pool doesn't accumulate noise from departed users /
      decommissioned hosts. Archival is a reversible flag, not a delete: the
      rows (and their baselines/outliers) remain queryable for audit, archived
      entities are excluded from later sweeps and from cross-entity similarity
      search, and observing the entity again revives it automatically.
    * **Baseline rebuild** — gated on ``behavioral_schedule_enabled``. When on,
      the job pulls last-``behavioral_stale_after_days`` EDR process telemetry
      per host from the mock-first CrowdStrike MCP, embeds each host's cmdlines
      via the configured embedding service, and builds one fresh baseline
      window per host (see
      :func:`behavioral_ingest_service.rebuild_baselines_from_edr`). When off
      (the default with mocks off, since the CrowdStrike live path raises), the
      build half is skipped with a single clear "no telemetry source wired"
      warning per tick rather than fabricating data. An operator who has wired
      a live EDR feed forces it on via ``BTAGENT_BEHAVIORAL_SCHEDULE_ENABLED=true``.

    Org scope: v1 rebuilds baselines for the **default org** (mirrors the other
    scheduled hunt jobs — there is no per-org EDR binding yet).

    Returns the sweep counts so they show up in arq's job result + our logs.
    """
    settings = get_settings()
    from datetime import timedelta

    from btagent_backend.services import behavioral_service

    baselines_built = 0
    async with async_session_factory() as session:
        stale_count, archived_count = await behavioral_service.archive_stale_entities(
            session,
            stale_after=timedelta(days=settings.behavioral_stale_after_days),
        )
        if settings.behavioral_schedule_enabled:
            # Lazy import: the rebuild path pulls the agents MCP stack.
            from btagent_backend.services import behavioral_ingest_service

            summary = await behavioral_ingest_service.rebuild_baselines_from_edr(
                session,
                org_id=DEFAULT_ORG_ID,
                lookback_days=settings.behavioral_stale_after_days,
            )
            baselines_built = summary["baselines_built"]
        # The single commit lives here — it persists both the archival stamps
        # and the rebuild half's new entity/profile rows.
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

    counts = {
        "stale_entities": stale_count,
        "entities_archived": archived_count,
        "baselines_built": baselines_built,
    }
    logger.info("behavioral_baseline_sweep: %s", counts)
    return counts


async def compile_proposal_plan(ctx: dict[str, Any], plan_row_id: str) -> dict[str, str]:
    """Compile an accepted proposal's HuntInput into its HuntPlan (#120 Phase C).

    Enqueue-on-demand: the pattern-hunt accept route enqueues this on the
    live-LLM path so the multi-round-trip compile never rides the synchronous
    HTTP accept (under mock LLM the route compiles inline instead). The
    service lands ``ready``/``failed`` on the row; either way the single
    commit happens here.
    """
    # Lazy import — the compile path pulls the engine stack.
    from btagent_backend.services import hunt_plan_service

    async with async_session_factory() as session:
        row = await hunt_plan_service.compile_and_store(session, plan_row_id=plan_row_id)
        await session.commit()
    logger.info("compile_proposal_plan %s: %s", plan_row_id, row.status)
    return {"plan_row_id": row.id, "status": row.status}


async def execute_hunt_plan(ctx: dict[str, Any], plan_row_id: str) -> dict[str, Any]:
    """Execute a compiled HuntPlan and ingest its hits (#120 Phase C).

    Enqueue-on-demand from the pattern-hunt execute route on the
    live-connector path (mock mode executes inline in the route) — live
    backend searches must not ride the synchronous HTTP request. The single
    commit happens here.
    """
    # Lazy import — the execute path pulls the engine integration stack.
    from btagent_backend.services import hunt_plan_service

    async with async_session_factory() as session:
        row, findings_created = await hunt_plan_service.execute_plan_and_ingest(
            session, plan_row_id=plan_row_id
        )
        await session.commit()
    logger.info("execute_hunt_plan %s: findings=%d", plan_row_id, findings_created)
    return {"plan_row_id": row.id, "findings_created": findings_created}


async def validate_detection_proposal(
    ctx: dict[str, Any],
    row_id: str,
    org_id: str,
    backends: list[str] | None = None,
    lookback_hours: int = 720,
) -> dict[str, Any]:
    """Validate a detection proposal against historical telemetry (#113 slice 2).

    Enqueue-on-demand from the CTI validate route on the live-connector path
    (mock mode validates inline in the route). The single commit happens here.
    """
    # Lazy import — the validate path pulls the engine pySigma stack.
    from btagent_backend.services import cti_detection_service

    async with async_session_factory() as session:
        row = await cti_detection_service.validate_proposal(
            session,
            org_id=org_id,
            row_id=row_id,
            backends=backends,
            lookback_hours=lookback_hours,
        )
        await session.commit()
    verdict = (row.validation or {}).get("verdict", "unknown")
    logger.info("validate_detection_proposal %s: verdict=%s", row_id, verdict)
    return {"row_id": row.id, "verdict": verdict}


async def noise_digest_sweep(ctx: dict[str, Any]) -> dict[str, int]:
    """Daily newly-noisy digest (#112): diff the noise baseline per org.

    For every org with pack-run history, compares the current noise baseline
    against the stored ``noise_digest_state`` and notifies hunt seniors about
    rules that turned chronically noisy since the previous sweep. The arq
    redis (``ctx["redis"]``) rides along for the real-time WS push; the DB
    rows are the source of truth either way.

    The sweep also *counts* the mirror-image signal — rules with a 60-day
    zero-hit record (#112 Phase C) — so the loop reports both halves of rule
    health. Silent rules are surfaced for review (``GET /hunt/under-firing``)
    and deliberately never notify; see :mod:`services.noise_digest`.
    """
    from sqlalchemy import select as _select

    from btagent_backend.db.models_hunt import HuntPackRunRow
    from btagent_backend.services.noise_digest import run_noise_digest

    totals = {"orgs": 0, "noisy": 0, "new": 0, "notified": 0, "under_firing": 0}
    async with async_session_factory() as session:
        org_ids = [
            org_id
            for (org_id,) in (
                await session.execute(_select(HuntPackRunRow.org_id).distinct())
            ).all()
        ]
        for org_id in org_ids:
            result = await run_noise_digest(session, org_id=org_id, redis=ctx.get("redis"))
            totals["orgs"] += 1
            for key in ("noisy", "new", "notified", "under_firing"):
                totals[key] += result.get(key, 0)
        await session.commit()
    logger.info(
        "noise_digest_sweep: orgs=%d noisy=%d new=%d notified=%d under_firing=%d",
        totals["orgs"],
        totals["noisy"],
        totals["new"],
        totals["notified"],
        totals["under_firing"],
    )
    return totals


async def shift_handover_digest(ctx: dict[str, Any]) -> dict[str, int]:
    """Shift-boundary handover digest (#108 UC-5.1).

    For every organization, builds the 8h handover rollup and pushes the
    headline to each analyst's bell (quiet windows stay silent — see
    :mod:`services.handover_notifier`). Fires at the three shift boundaries;
    the arq redis rides along for the real-time WS push.
    """
    from sqlalchemy import select as _select

    from btagent_backend.db.models import OrganizationRow
    from btagent_backend.services.handover_notifier import notify_shift_handover

    totals = {"orgs": 0, "notified": 0}
    async with async_session_factory() as session:
        org_ids = [
            org_id for (org_id,) in (await session.execute(_select(OrganizationRow.id))).all()
        ]
        for org_id in org_ids:
            created = await notify_shift_handover(session, org_id=org_id, redis=ctx.get("redis"))
            totals["orgs"] += 1
            totals["notified"] += len(created)
        await session.commit()
    logger.info("shift_handover_digest: orgs=%d notified=%d", totals["orgs"], totals["notified"])
    return totals


async def execute_workflow_run(ctx: dict[str, Any], run_id: str) -> dict[str, Any]:
    """Execute a background workflow run created by the run route.

    Enqueue-on-demand (no cron). Idempotent against redelivery via the
    service's running-state check. After execution the trigger user hears
    about the outcome: paused runs go through the standard pause notifiers
    (trigger + approver fan-out), terminal runs get a finished/failed notice.
    """
    from btagent_shared.types.workflow import WorkflowRunStatus

    from btagent_backend.db.models_workflow import WorkflowRow
    from btagent_backend.services import workflow_run_service
    from btagent_backend.services.hitl_notifier import (
        notify_workflow_finished,
        notify_workflow_paused,
        notify_workflow_paused_approvers,
    )

    async with async_session_factory() as session:
        run = await workflow_run_service.execute_pending_run(session, run_id=run_id)
        if run is None:
            return {"run_id": run_id, "status": "skipped"}

        workflow = await session.get(WorkflowRow, run.workflow_id)
        if workflow is not None:
            try:
                if run.status == WorkflowRunStatus.PAUSED.value:
                    await notify_workflow_paused(
                        session, workflow=workflow, run=run, redis=ctx.get("redis")
                    )
                    await notify_workflow_paused_approvers(
                        session, workflow=workflow, run=run, redis=ctx.get("redis")
                    )
                else:
                    await notify_workflow_finished(
                        session, workflow=workflow, run=run, redis=ctx.get("redis")
                    )
            except Exception:
                logger.exception("Background run %s: outcome notification failed", run_id)
        await session.commit()
    logger.info("execute_workflow_run %s: status=%s", run_id, run.status)
    return {"run_id": run_id, "status": run.status}
