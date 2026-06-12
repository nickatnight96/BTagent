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
* :func:`run_pack_and_ingest` — orchestration: loads the builtin packs, runs
  them through the engine runner against the configured backends, converts,
  persists, and (best-effort) emits the run events.

Per the codebase convention the persistence helpers never commit — the arq
job wrapper owns the commit. Event emission follows the ``TaskManager``
precedent (a backend-side service *does* emit, via a short-lived
``RedisEmitter`` keyed on the run id) rather than the route layer, because a
scheduled run has no HTTP request to hang emission off.

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
from btagent_backend.services import hunt_triage_service

if TYPE_CHECKING:  # avoid importing the (pysigma-heavy) engine at module load
    from btagent_engine.hunting.runner import PackRunResult, SigmaHit

logger = logging.getLogger("btagent.services.hunt_pack_run")

# Cap on the JSON size of the raw event copied into a finding's evidence. A
# typical SIEM row is well under this; a pathological one is truncated to a
# preview so the findings table can't be bloated by one runaway event.
_RAW_EVIDENCE_CAP_BYTES = 4096
# How much of an over-cap raw event to keep as a human-readable preview.
_RAW_PREVIEW_CHARS = 512

# The builtin packs run by the scheduled job. v1 ships the one builtin pack;
# enabling/disabling per-org is a follow-up (the pack store, #112 FE).
DEFAULT_BUILTIN_PACKS: tuple[str, ...] = ("windows_baseline",)


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


def _rule_stats(result: PackRunResult) -> dict[str, dict[str, Any]]:
    """Per-rule hit/error rollup for the history row."""
    stats: dict[str, dict[str, Any]] = {}
    for rule in result.rule_results:
        stats[rule.rule_id] = {
            "title": rule.rule_title,
            "hits": rule.hit_count,
            "errors": len(rule.errors),
        }
    return stats


# --------------------------------------------------------------------------- #
# Persistence (no commit — the arq job wrapper commits)
# --------------------------------------------------------------------------- #


async def persist_pack_run(
    db: AsyncSession,
    *,
    org_id: str,
    result: PackRunResult,
    status: str | None = None,
    error: str | None = None,
) -> tuple[HuntPackRunRow, int]:
    """Ingest a run's hits into the #119 store and record its history row.

    Converts + dedupes the run's hits, lands them via
    :func:`hunt_triage_service.persist_hunt_findings` (so active suppressions
    are applied pre-insert), then writes a :class:`HuntPackRunRow`. Returns
    the history row and the number of findings created. Not committed.

    ``status`` is derived from the run's per-rule×backend execution outcomes
    when not supplied (Codex #202 P2 — see :func:`_derive_run_status`): a run
    where every execution errored is ``failed``; a partial one is
    ``completed_with_errors``; a clean one is ``completed``.
    """
    if status is None:
        status = _derive_run_status(result)
    requests = hits_to_finding_requests(result.all_hits)
    rows = await hunt_triage_service.persist_hunt_findings(db, org_id=org_id, findings=requests)

    run_row = HuntPackRunRow(
        id=generate_id("hpkrun"),
        org_id=org_id,
        run_id=result.run_id,
        pack_id=result.pack_id,
        pack_name=result.pack_name,
        pack_version=result.pack_version,
        backends=[str(b) for b in result.backends],
        rule_stats=_rule_stats(result),
        hit_count=len(result.all_hits),
        error_count=result.error_count,
        findings_created=len(rows),
        status=status,
        error=error,
        started_at=result.started_at,
        completed_at=result.completed_at,
    )
    db.add(run_row)
    await db.flush()
    return run_row, len(rows)


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
) -> list[HuntPackRunRow]:
    """Run the enabled builtin packs and land their hits in the triage inbox.

    Org-aware: ingests into ``org_id`` (the default org in v1 — scheduled
    runs have no per-org pack store yet; see ``DEFAULT_BUILTIN_PACKS``). One
    history row per pack. A failure running a single pack is captured as a
    ``failed`` history row and does not abort the rest. Not committed — the
    arq job wrapper commits once.
    """
    # Lazy: the engine pulls pysigma, only present in the worker image.
    from btagent_engine.hunting.pack import load_builtin_pack
    from btagent_engine.hunting.runner import run_pack
    from btagent_engine.node import NodeContext

    settings = get_settings()
    pack_names = list(pack_names or DEFAULT_BUILTIN_PACKS)
    backends = list(backends or settings.hunt_scheduler_backends)

    run_rows: list[HuntPackRunRow] = []
    for name in pack_names:
        try:
            pack = load_builtin_pack(name)
            ctx = NodeContext(run_id=generate_id("hrun"), org_id=org_id)
            result = await run_pack(
                pack,
                backends,
                ctx,
                lookback_hours=lookback_hours,
                max_hits_per_query=max_hits_per_query,
            )
            run_row, created = await persist_pack_run(db, org_id=org_id, result=result)
            run_rows.append(run_row)
            logger.info(
                "scheduled hunt pack run pack=%s run=%s hits=%d findings=%d errors=%d",
                pack.id,
                result.run_id,
                run_row.hit_count,
                created,
                run_row.error_count,
            )
            if emit_events:
                await _emit_run_events(org_id=org_id, run_row=run_row, redis_url=settings.redis_url)
        except Exception as exc:  # one bad pack must not kill the sweep
            logger.exception("scheduled hunt pack run failed: pack=%s", name)
            run_rows.append(
                await _record_failed_run(db, org_id=org_id, pack_name=name, error=str(exc))
            )
    return run_rows


async def _record_failed_run(
    db: AsyncSession, *, org_id: str, pack_name: str, error: str
) -> HuntPackRunRow:
    from datetime import UTC, datetime

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
