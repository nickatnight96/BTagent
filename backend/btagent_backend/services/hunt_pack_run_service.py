"""Hunt-pack run integration service — scheduled packs → triage inbox (#112).

This closes the integration seam documented in
``btagent_engine.hunting.runner``: it converts the engine runner's transient
:class:`~btagent_engine.hunting.runner.SigmaHit` objects into the #119
``HuntFinding`` store and records a *pack-run history* row (the substrate the
future noise baselines read).

Three layers, mirroring the rest of the hunt backend:

* :func:`sigma_hit_to_finding_request` / :func:`hits_to_finding_requests` —
  **pure** conversion (no DB / network), unit-testable in isolation. This is
  the mapping the runner's TODO points at.
* :func:`persist_pack_run` — the side-effectful shell: ingests the converted
  findings via :func:`hunt_triage_service.persist_hunt_findings` (so
  suppressions apply *pre-insert*) and writes the history row.
* :func:`run_pack_and_ingest` — orchestration: resolves which packs the org has
  enabled (:mod:`hunt_pack_store`), loads them, runs them through the engine
  runner against the configured backends, converts, persists, and
  (best-effort) emits the run events.

Resume-from-checkpoint (#112, "survives worker restart"): a pack run advertises
an in-flight ``running`` status and records, per rule, which rules it has
already converted + ingested under :attr:`HuntPackRunRow.progress`
(``{"completed_rule_ids": [...]}``). :func:`persist_pack_run` writes that cursor
**incrementally — one commit per rule** — so a worker that dies mid-run resumes
at the first not-yet-completed rule instead of re-doing finished work (and
re-emitting its findings). This is a deliberate exception to the usual
"persistence helpers never commit — the arq job wrapper owns the commit"
convention: durability across a restart *requires* the intermediate commits
(``checkpoint=True``, the default). Callers that want the old flush-only
behaviour (the whole run in one outer transaction) pass ``checkpoint=False``.

Event emission follows the ``TaskManager`` precedent (a backend-side service
*does* emit, via a short-lived ``RedisEmitter`` keyed on the run id) rather than
the route layer, because a scheduled run has no HTTP request to hang emission
off.

Mapping decisions (documented for review):

* ``SigmaHit.entities`` (``{kind, value}``) → finding ``entities`` verbatim
  (same shape as :class:`btagent_shared.types.hunt_finding.HuntEntity`).
* ``SigmaHit.observable`` / ``observable_type`` → a single finding
  ``observable`` (``{type, value}``) when both present; dropped otherwise.
* ``severity`` passes through unchanged from the rule's level.
* ``technique_ids`` = ``SigmaHit.mitre_techniques``.
* ``source`` = ``HuntSource.HUNT_PACK``; ``domain`` = ``HuntDomain.SIGMA``.
* ``title`` = ``rule_title`` plus the primary entity (``" — host=…"``) so
  near-identical rule hits read distinctly in the inbox.
* ``evidence`` carries the provenance the analyst needs to pivot back to the
  detection — ``pack_id``, ``rule_id``, ``rule_title``, ``backend``,
  ``source_run_id``, ``summary`` — plus a **size-capped** copy of the raw
  event under ``raw`` (see ``_RAW_EVIDENCE_CAP_BYTES``: the raw dict is kept
  whole if its JSON is under the cap, else it is replaced by a
  ``{"_truncated": true, "_preview": "<first N chars>"}`` stub so a runaway
  event payload can't bloat the findings table).

Dedupe decision (documented): within a single run the same rule firing many
times for the same host/observable produces duplicate hits (mock connectors
demonstrably do this). We dedupe on the stable key
``(rule_id, backend, tuple(sorted entity (kind, value) pairs),
observable_type, observable)`` and keep the first hit per key. This collapses
true duplicates while preserving distinct entities/observables of the same
rule — including the kind, so ``host=alice`` and ``user=alice`` stay distinct,
and the observable type so an IP and a domain with the same string don't
collide.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from btagent_shared.types.enums import Severity
from btagent_shared.types.hunt import HuntDomain, HuntSource
from btagent_shared.types.hunt_finding import (
    HuntEntity,
    HuntObservable,
    RecordFindingRequest,
)
from btagent_shared.utils.ids import generate_id
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.config import get_settings
from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_hunt import HuntPackRunRow
from btagent_backend.services import hunt_pack_store, hunt_triage_service, org_custom_pack_service

if TYPE_CHECKING:  # avoid importing the (pysigma-heavy) engine at module load
    from btagent_engine.hunting.runner import PackRunResult, RuleRunResult, SigmaHit

logger = logging.getLogger("btagent.services.hunt_pack_run")

# Cap on the JSON size of the raw event copied into a finding's evidence. A
# typical SIEM row is well under this; a pathological one is truncated to a
# preview so the findings table can't be bloated by one runaway event.
_RAW_EVIDENCE_CAP_BYTES = 4096
# How much of an over-cap raw event to keep as a human-readable preview.
_RAW_PREVIEW_CHARS = 512

# The packs a scheduled sweep runs for an org with no rows in the per-org pack
# store. The store (:mod:`hunt_pack_store`) owns the enable/disable decision
# now; this alias keeps the historical import path working.
DEFAULT_BUILTIN_PACKS: tuple[str, ...] = hunt_pack_store.DEFAULT_BUILTIN_PACKS

# In-flight status a resumable run wears until it lands a terminal status.
_RUNNING = "running"

# Terminal status for a ``running`` row nobody resumed inside the window.
# Deliberately distinct from ``failed``: the run did not error, it was
# orphaned, and an analyst reading history should be able to tell those
# apart when deciding whether coverage actually ran.
_ABANDONED = "abandoned"


# --------------------------------------------------------------------------- #
# Pure conversion (no DB / network) — the runner's documented integration seam
# --------------------------------------------------------------------------- #


def _cap_raw(raw: dict[str, Any]) -> dict[str, Any]:
    """Return ``raw`` whole if small, else a truncated preview stub."""
    if not raw:
        return {}
    try:
        encoded = json.dumps(raw, default=str)
    except (TypeError, ValueError):
        encoded = str(raw)
    if len(encoded.encode("utf-8")) <= _RAW_EVIDENCE_CAP_BYTES:
        return dict(raw)
    return {"_truncated": True, "_preview": encoded[:_RAW_PREVIEW_CHARS]}


def _dedupe_key(
    hit: SigmaHit,
) -> tuple[str, str, tuple[tuple[str, str], ...], str | None, str | None]:
    """Stable within-run identity for a hit (see module docstring).

    Codex #202 P2: the key includes each entity's ``(kind, value)`` pair (not
    just the value) and the ``observable_type``, so ``host=alice`` and
    ``user=alice`` — or an IP vs a domain with the same string — no longer
    collide into one finding.
    """
    entity_pairs = tuple(sorted((e.kind, e.value) for e in hit.entities))
    return (hit.rule_id, hit.backend, entity_pairs, hit.observable_type, hit.observable)


def _title_for(hit: SigmaHit) -> str:
    """``rule_title`` + the primary entity so duplicate rules read distinctly."""
    if hit.entities:
        ent = hit.entities[0]
        return f"{hit.rule_title} — {ent.kind}={ent.value}"[:300]
    if hit.observable:
        return f"{hit.rule_title} — {hit.observable}"[:300]
    return hit.rule_title[:300]


def sigma_hit_to_finding_request(hit: SigmaHit) -> RecordFindingRequest:
    """Convert one engine :class:`SigmaHit` into a :class:`RecordFindingRequest`.

    Pure: no DB, no network. This is the mapping the runner's TODO points at.
    """
    observables: list[HuntObservable] = []
    if hit.observable and hit.observable_type:
        observables.append(HuntObservable(type=hit.observable_type, value=hit.observable))

    evidence: dict[str, Any] = {
        "pack_id": hit.pack_id,
        "rule_id": hit.rule_id,
        "rule_title": hit.rule_title,
        "backend": hit.backend,
        "source_run_id": hit.source_run_id,
        "summary": hit.summary,
        "raw": _cap_raw(hit.raw),
    }

    return RecordFindingRequest(
        source=HuntSource.HUNT_PACK,
        domain=HuntDomain.SIGMA,
        title=_title_for(hit),
        description=hit.summary,
        severity=hit.severity if isinstance(hit.severity, Severity) else Severity(hit.severity),
        technique_ids=list(hit.mitre_techniques),
        entities=[HuntEntity(kind=e.kind, value=e.value) for e in hit.entities],
        observables=observables,
        evidence=evidence,
    )


def hits_to_finding_requests(hits: Iterable[SigmaHit]) -> list[RecordFindingRequest]:
    """Convert a batch of hits, deduping identical hits within the batch.

    Dedupe key: ``(rule_id, backend, sorted entity (kind, value) pairs,
    observable_type, observable)`` — the first hit per key wins. Order is
    preserved.
    """
    seen: set[tuple[str, str, tuple[tuple[str, str], ...], str | None, str | None]] = set()
    out: list[RecordFindingRequest] = []
    for hit in hits:
        key = _dedupe_key(hit)
        if key in seen:
            continue
        seen.add(key)
        out.append(sigma_hit_to_finding_request(hit))
    return out


def _derive_run_status(result: PackRunResult) -> str:
    """Codex #202 P2: a run's status must reflect its execution errors.

    Counts every rule×backend execution outcome:

    * ``failed`` — EVERY execution errored (transpile or run); there were
      executions and none succeeded, so the run produced nothing useful.
    * ``completed_with_errors`` — some executions errored and some succeeded
      (partial result; the analyst should know the picture is incomplete).
    * ``completed`` — no execution errored.

    A run with no executions at all (empty pack) has ``error_count == 0`` and
    is treated as ``completed`` — there was nothing to fail.
    """
    errored = 0
    succeeded = 0
    for rule in result.rule_results:
        for backend in rule.backend_results:
            if backend.error:
                errored += 1
            else:
                succeeded += 1
    if errored == 0:
        return "completed"
    if succeeded == 0:
        return "failed"
    return "completed_with_errors"


def _rule_stat_entry(rule: RuleRunResult) -> dict[str, Any]:
    """One rule's rollup for the history row's ``rule_stats`` map.

    ``{"title", "hits", "errors", "queries"}`` — ``queries`` is the transpiled
    query string per backend (``{backend: query}``, omitting backends whose
    transpile itself failed). The Phase-B HuntPacks view reads it to render the
    per-backend query in a rule's detail panel; the noise baseline ignores the
    extra keys (it only reads ``hits`` / ``title``).
    """
    return {
        "title": rule.rule_title,
        "hits": rule.hit_count,
        "errors": len(rule.errors),
        "queries": {b.backend: b.query for b in rule.backend_results if b.query},
    }


# --------------------------------------------------------------------------- #
# Persistence (no commit — the arq job wrapper commits)
# --------------------------------------------------------------------------- #


def _completed_rule_ids(run_row: HuntPackRunRow) -> list[str]:
    """The rules already converted + ingested for ``run_row`` (resume cursor)."""
    return list((run_row.progress or {}).get("completed_rule_ids", []))


async def _find_resumable_run(
    db: AsyncSession, *, org_id: str, pack_id: str
) -> HuntPackRunRow | None:
    """The newest *recent* in-flight run for one org's pack, or ``None``.

    A worker restart calls this to pick up where the previous invocation left
    off. Keyed on ``(org_id, pack_id, status)`` — served by the composite index
    added in migration 0055.

    Bounded by ``hunt_run_resume_window_minutes`` (60 by default), and the
    bound is the point. Resumption is for a *restart*, not for the next
    scheduled tick. Unbounded, a run orphaned by a permanently-dead worker sits
    at ``running`` forever, so the next scheduled sweep adopts its progress
    cursor, skips *persisting* every rule the dead run had completed — throwing
    away that sweep's freshly-executed hits — and then stamps the dead row
    terminal under its original timestamp. One sweep of coverage lost, silently,
    filed against the wrong run.

    A candidate outside the window is abandoned rather than ignored: it is
    stamped ``failed`` so the history stops claiming it is still running, and so
    it cannot be picked up again. The caller then opens a fresh row and ingests
    everything.
    """
    cutoff = datetime.now(UTC) - timedelta(minutes=get_settings().hunt_run_resume_window_minutes)
    result = await db.execute(
        select(HuntPackRunRow)
        .where(
            HuntPackRunRow.org_id == org_id,
            HuntPackRunRow.pack_id == pack_id,
            HuntPackRunRow.status == _RUNNING,
        )
        .order_by(HuntPackRunRow.started_at.desc())
        .limit(1)
    )
    row = result.scalar_one_or_none()
    if row is None:
        return None

    started = row.started_at
    if started is not None and started.tzinfo is None:
        # SQLite (and any naive-datetime column) hands back tz-naive values;
        # the rows are written in UTC, so attach it rather than comparing a
        # naive to an aware datetime and raising.
        started = started.replace(tzinfo=UTC)

    if started is not None and started < cutoff:
        logger.info(
            "abandoning stale running pack-run %s (org=%s pack=%s started=%s); "
            "outside the %s-minute resume window",
            row.id,
            org_id,
            pack_id,
            started.isoformat(),
            get_settings().hunt_run_resume_window_minutes,
        )
        row.status = _ABANDONED
        # E7: an abandoned sweep is not a clean one — some rules never ran.
        # Reusing the existing truncation flag makes it read correctly in run
        # history without every consumer learning a new status.
        row.truncated = True
        row.error = (
            "abandoned: no worker resumed this run within the "
            f"{get_settings().hunt_run_resume_window_minutes}-minute resume window"
        )
        row.completed_at = datetime.now(UTC)
        await db.flush()
        return None

    return row


def _new_running_row(*, org_id: str, result: PackRunResult) -> HuntPackRunRow:
    """A fresh ``running`` history row with an empty resume cursor."""
    return HuntPackRunRow(
        id=generate_id("hpkrun"),
        org_id=org_id,
        run_id=result.run_id,
        pack_id=result.pack_id,
        pack_name=result.pack_name,
        pack_version=result.pack_version,
        backends=[str(b) for b in result.backends],
        rule_stats={},
        hit_count=0,
        error_count=0,
        findings_created=0,
        status=_RUNNING,
        progress={"completed_rule_ids": []},
        started_at=result.started_at,
        completed_at=None,
    )


async def persist_pack_run(
    db: AsyncSession,
    *,
    org_id: str,
    result: PackRunResult,
    status: str | None = None,
    error: str | None = None,
    run_row: HuntPackRunRow | None = None,
    checkpoint: bool = True,
) -> tuple[HuntPackRunRow, int]:
    """Ingest a run's hits into the #119 store and record its history row.

    Processes the run **rule by rule** so the work is resumable (#112). For
    each rule not already in the row's resume cursor
    (:attr:`HuntPackRunRow.progress`) it converts + dedupes that rule's hits,
    lands them via :func:`hunt_triage_service.persist_hunt_findings` (so active
    suppressions apply pre-insert), accumulates the row's counters +
    ``rule_stats``, appends the rule to the cursor, and — when
    ``checkpoint`` — commits. A worker that dies part-way therefore leaves a
    ``running`` row whose cursor names the rules already done; a later call
    with the same ``result`` + ``run_row`` skips them and picks up at the next
    rule. Findings that were already ingested are never re-created.

    ``run_row`` is the row to resume (from :func:`_find_resumable_run`); when
    ``None`` a fresh ``running`` row is created for this run. The row's
    counters are **cumulative** across resumes; the returned int is the number
    of findings created *in this call* (the not-yet-completed rules only).

    ``status`` is the terminal status stamped once every rule is done; when not
    supplied it is derived from the run's per-rule×backend execution outcomes
    (Codex #202 P2 — see :func:`_derive_run_status`): a run where every
    execution errored is ``failed``; a partial one is ``completed_with_errors``;
    a clean one is ``completed``.
    """
    if run_row is None:
        run_row = _new_running_row(org_id=org_id, result=result)
        db.add(run_row)
        await db.flush()

    completed = _completed_rule_ids(run_row)
    completed_set = set(completed)
    created_this_call = 0

    for rule in result.rule_results:
        if rule.rule_id in completed_set:
            continue
        rule_hits = [hit for backend in rule.backend_results for hit in backend.hits]
        requests = hits_to_finding_requests(rule_hits)
        rows = await hunt_triage_service.persist_hunt_findings(db, org_id=org_id, findings=requests)

        # Accumulate onto the row (reassign JSON columns so SQLAlchemy sees the
        # change — in-place mutation of a plain JSON column is not tracked).
        run_row.hit_count += rule.hit_count
        run_row.error_count += len(rule.errors)
        run_row.findings_created += len(rows)
        created_this_call += len(rows)
        stats = dict(run_row.rule_stats or {})
        stats[rule.rule_id] = _rule_stat_entry(rule)
        run_row.rule_stats = stats
        completed.append(rule.rule_id)
        completed_set.add(rule.rule_id)
        run_row.progress = {"completed_rule_ids": completed}

        await db.flush()
        if checkpoint:
            await db.commit()

    # Every rule done — land the terminal status + completion timestamp.
    run_row.status = status if status is not None else _derive_run_status(result)
    run_row.error = error
    run_row.completed_at = result.completed_at
    # E7: carry the runner's coverage verdict onto the history row. A run the
    # rules-per-sweep cap or the per-run deadline stopped early is NOT a clean
    # sweep, and the difference is invisible from hit counts alone — a capped
    # run that found nothing looks exactly like a full run that found nothing.
    run_row.truncated = bool(result.truncated)
    run_row.rules_not_run = list(result.rules_not_run)
    await db.flush()
    if checkpoint:
        await db.commit()
    return run_row, created_this_call


async def list_pack_runs(
    db: AsyncSession,
    *,
    org_id: str,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[HuntPackRunRow], int]:
    """Org-scoped pack-run history, newest-first, paginated."""
    offset = (page - 1) * page_size
    total = (
        await db.execute(
            select(func.count()).select_from(HuntPackRunRow).where(HuntPackRunRow.org_id == org_id)
        )
    ).scalar_one() or 0
    rows = (
        (
            await db.execute(
                select(HuntPackRunRow)
                .where(HuntPackRunRow.org_id == org_id)
                .order_by(HuntPackRunRow.started_at.desc())
                .offset(offset)
                .limit(page_size)
            )
        )
        .scalars()
        .all()
    )
    return list(rows), int(total)


# --------------------------------------------------------------------------- #
# Ad-hoc single-rule install (#113 Phase C closed loop)
# --------------------------------------------------------------------------- #


async def run_adhoc_rule_pack(
    db: AsyncSession,
    *,
    org_id: str,
    rule_id: str,
    title: str,
    sigma_yaml: str,
    technique_ids: Sequence[str] | None = None,
    backends: Sequence[str] | None = None,
    lookback_hours: int = 24,
    checkpoint: bool = False,
    emit_events: bool = False,
) -> HuntPackRunRow:
    """Install + run a single ad-hoc Sigma rule as a one-off #112 hunt pack.

    The "auto-install as a #112 hunt-pack entry" step of the CTI → Detection
    closed loop (#113 Phase C): a merged detection rule is wrapped in a
    one-rule :class:`~btagent_engine.hunting.pack.HuntPack` and run through the
    exact same transpile → execute → convert → ingest pipeline the scheduled
    packs use, so the merged rule immediately hunts current telemetry and lands
    its hits in the #119 triage inbox. A :class:`HuntPackRunRow` records the
    install as a first-class pack-run history fact.

    Mock-first (``BTAGENT_MOCK_CONNECTORS`` default on). Defaults to
    ``checkpoint=False`` / ``emit_events=False`` so it composes cleanly inside a
    caller's transaction or savepoint (the closed loop runs it under a nested
    savepoint) — the caller owns the commit.
    """
    import yaml as _yaml

    # Lazy: the engine pulls pysigma, only present in the worker/engine image.
    from btagent_engine.hunting.pack import HuntPack, HuntPackRule, extract_techniques
    from btagent_engine.hunting.runner import run_pack
    from btagent_engine.node import NodeContext

    settings = get_settings()
    backend_list = list(backends or settings.hunt_scheduler_backends)

    parsed = _yaml.safe_load(sigma_yaml) if sigma_yaml else None
    if not isinstance(parsed, dict):
        parsed = {}
    logsource = {
        str(k): str(v) for k, v in (parsed.get("logsource") or {}).items() if v is not None
    }
    techniques = list(technique_ids or []) or extract_techniques(parsed.get("tags", []) or [])

    rule = HuntPackRule(
        id=(rule_id or generate_id("hrule"))[:200],
        title=(title or "CTI-derived detection")[:300],
        sigma_yaml=sigma_yaml,
        logsource=logsource,
        mitre_techniques=techniques,
    )
    pack = HuntPack(
        id=f"cti-merged-{rule_id}"[:200],
        name=f"CTI merged: {title}"[:200] or "CTI merged rule",
        version="1",
        description="Auto-installed from a merged CTI → Detection rule (#113 Phase C).",
        rules=[rule],
    )

    run_id = generate_id("hrun")
    ctx = NodeContext(run_id=run_id, org_id=org_id)
    result = await run_pack(pack, backend_list, ctx, lookback_hours=lookback_hours, run_id=run_id)
    run_row, created = await persist_pack_run(
        db, org_id=org_id, result=result, checkpoint=checkpoint
    )
    logger.info(
        "ad-hoc CTI rule installed as hunt pack: run=%s rule=%s hits=%d findings=%d (org=%s)",
        run_row.run_id,
        rule.id,
        run_row.hit_count,
        created,
        org_id,
    )
    if emit_events:
        await _emit_run_events(org_id=org_id, run_row=run_row, redis_url=settings.redis_url)
    return run_row


# --------------------------------------------------------------------------- #
# Orchestration — load builtin packs, run, convert, persist, emit
# --------------------------------------------------------------------------- #


async def run_pack_and_ingest(
    db: AsyncSession,
    *,
    org_id: str = DEFAULT_ORG_ID,
    pack_names: Sequence[str] | None = None,
    backends: Sequence[str] | None = None,
    lookback_hours: int = 24,
    max_hits_per_query: int = 100,
    emit_events: bool = True,
    checkpoint: bool = True,
) -> list[HuntPackRunRow]:
    """Run the org's enabled packs and land their hits in the triage inbox.

    Org-aware: ingests into ``org_id`` and — when ``pack_names`` is not given —
    runs exactly the packs that org has **enabled** in the per-org pack store
    (:func:`hunt_pack_store.enabled_pack_names`), resolving each name through
    :func:`hunt_pack_store.load_pack_for_org` so an externally imported corpus
    (#112 ``bt huntpack install``) runs alongside the shipped packs. An org
    with no rows falls back to the builtin default set, so behaviour for
    existing orgs is unchanged. An explicit ``pack_names`` (ad-hoc / test runs)
    bypasses the store. One history row per pack; a failure running a single
    pack is captured as a ``failed`` history row and does not abort the rest.

    Resume-aware (#112): before running a pack it looks for the newest
    in-flight (``running``) run for ``(org_id, pack)`` — the remnant of a
    worker that died mid-run — and resumes it, reusing its stable ``run_id``
    (so findings ingested before and after the restart correlate to one run)
    and skipping the rules already checkpointed. With ``checkpoint`` the
    per-rule progress is committed as it lands, so the resume survives a real
    process restart; the arq job wrapper still owns the final commit.
    """
    # Lazy: the engine pulls pysigma, only present in the worker image.
    from btagent_engine.hunting.runner import run_pack
    from btagent_engine.node import NodeContext

    settings = get_settings()
    # Org-custom packs (#112 slice 2) run alongside the builtin set: their
    # sweep "name" is the stored pack_id, resolved to a bundle row below
    # instead of a builtin directory. An explicit ``pack_names`` (ad-hoc /
    # test runs) still bypasses both stores.
    custom_by_pack_id: dict[str, object] = {}
    if pack_names is None:
        pack_names = await hunt_pack_store.enabled_pack_names(db, org_id=org_id)
        custom_rows = await org_custom_pack_service.list_packs(db, org_id=org_id)
        custom_by_pack_id = {r.pack_id: r for r in custom_rows}
        pack_names = list(pack_names) + list(custom_by_pack_id)
    else:
        pack_names = list(pack_names)
    backends = list(backends or settings.hunt_scheduler_backends)
    if not pack_names:
        # Every pack explicitly disabled for this org — a legitimate state, not
        # an error. Say so once rather than silently returning nothing.
        logger.info("no hunt packs enabled for org=%s; skipping sweep", org_id)
        return []

    run_rows: list[HuntPackRunRow] = []
    for name in pack_names:
        run_row: HuntPackRunRow | None = None
        try:
            # Three pack sources, most-specific first:
            #   1. org custom packs stored as DB rows,
            #   2. externally imported corpus packs installed on disk (#112),
            #   3. the shipped builtins.
            # ``load_pack_for_org`` covers (2) then (3), so an imported SigmaHQ
            # corpus runs the exact same transpile → execute → ingest pipeline
            # as a shipped pack.
            custom_row = custom_by_pack_id.get(name)
            if custom_row is not None:
                pack = org_custom_pack_service.load_row_pack(custom_row)
            else:
                pack = hunt_pack_store.load_pack_for_org(name, org_id=org_id)
            # Resume the in-flight run for this pack if one survived a restart,
            # else open a fresh one. Either way we run against its stable id.
            run_row = await _find_resumable_run(db, org_id=org_id, pack_id=pack.id)
            if run_row is None:
                run_row = HuntPackRunRow(
                    id=generate_id("hpkrun"),
                    org_id=org_id,
                    run_id=generate_id("hrun"),
                    pack_id=pack.id,
                    pack_name=pack.name,
                    pack_version=pack.version,
                    backends=[str(b) for b in backends],
                    rule_stats={},
                    hit_count=0,
                    error_count=0,
                    findings_created=0,
                    status=_RUNNING,
                    progress={"completed_rule_ids": []},
                    started_at=datetime.now(UTC),
                    completed_at=None,
                )
                db.add(run_row)
                await db.flush()
                if checkpoint:
                    await db.commit()
            ctx = NodeContext(run_id=run_row.run_id, org_id=org_id)
            result = await run_pack(
                pack,
                backends,
                ctx,
                lookback_hours=lookback_hours,
                max_hits_per_query=max_hits_per_query,
                run_id=run_row.run_id,
            )
            run_row, created = await persist_pack_run(
                db, org_id=org_id, result=result, run_row=run_row, checkpoint=checkpoint
            )
            run_rows.append(run_row)
            logger.info(
                "scheduled hunt pack run pack=%s run=%s hits=%d findings=%d errors=%d",
                pack.id,
                run_row.run_id,
                run_row.hit_count,
                created,
                run_row.error_count,
            )
            if emit_events:
                await _emit_run_events(org_id=org_id, run_row=run_row, redis_url=settings.redis_url)
        except Exception as exc:  # one bad pack must not kill the sweep
            logger.exception("scheduled hunt pack run failed: pack=%s", name)
            # Clear any half-open transaction from the failing rule so the next
            # pack in the sweep starts clean; committed checkpoints survive the
            # rollback.
            pack_id = run_row.pack_id if run_row is not None else None
            await db.rollback()
            # A run that got far enough to commit its ``running`` row has its
            # progress checkpointed; leave it in place so the next invocation
            # resumes it rather than burying it under a ``failed`` row. Only
            # record a failed row when nothing resumable survived (e.g. the pack
            # failed to load, or the row was never committed).
            resumable = (
                await _find_resumable_run(db, org_id=org_id, pack_id=pack_id) if pack_id else None
            )
            if resumable is not None:
                run_rows.append(resumable)
            else:
                run_rows.append(
                    await _record_failed_run(db, org_id=org_id, pack_name=name, error=str(exc))
                )
    return run_rows


async def _record_failed_run(
    db: AsyncSession, *, org_id: str, pack_name: str, error: str
) -> HuntPackRunRow:
    now = datetime.now(UTC)
    row = HuntPackRunRow(
        id=generate_id("hpkrun"),
        org_id=org_id,
        run_id=generate_id("hrun"),
        pack_id="",
        pack_name=pack_name,
        pack_version="",
        backends=[],
        rule_stats={},
        hit_count=0,
        error_count=0,
        findings_created=0,
        status="failed",
        error=error[:2048],
        started_at=now,
        completed_at=now,
    )
    db.add(row)
    await db.flush()
    return row


async def _emit_run_events(*, org_id: str, run_row: HuntPackRunRow, redis_url: str) -> None:
    """Best-effort Redis emission of the run's batched events.

    Follows the ``TaskManager`` precedent (a backend-side service emits via a
    short-lived :class:`RedisEmitter`) rather than the route layer, since a
    scheduled run has no HTTP request. Keyed on the run id so the UI can
    subscribe to a run stream. Emission is best-effort: a Redis hiccup (or the
    agents package not being installed) must never fail the run — the findings
    are already persisted by the time we get here.

    Batched per run, not per finding: one ``HUNT_FINDING_CREATED`` carrying the
    count, plus one ``HUNT_STARTED``-style run-complete event.
    """
    try:
        from btagent_agents.events.emitter import RedisEmitter
        from btagent_shared.types.events import EventType
    except Exception:
        return

    emitter: Any = None
    try:
        emitter = RedisEmitter(run_row.run_id, redis_url)
        await emitter.connect()
        if run_row.findings_created:
            await emitter.emit(
                EventType.HUNT_FINDING_CREATED,
                org_id=org_id,
                pack_id=run_row.pack_id,
                run_id=run_row.run_id,
                count=run_row.findings_created,
            )
        await emitter.emit(
            EventType.HUNT_STARTED,
            org_id=org_id,
            pack_id=run_row.pack_id,
            run_id=run_row.run_id,
            status=run_row.status,
            hit_count=run_row.hit_count,
            findings_created=run_row.findings_created,
            error_count=run_row.error_count,
        )
    except Exception:
        logger.warning("hunt pack-run event emission failed (non-fatal)", exc_info=True)
    finally:
        if emitter is not None:
            try:
                await emitter.close()
            except Exception:
                pass
