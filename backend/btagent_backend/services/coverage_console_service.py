"""Coverage Console aggregation (#501) — one composed read over four surfaces.

The detection-engineering loop (#98 Bet 1) was **built** but **invisible**: the
evidence lived in four unrelated places and no single screen answered *what do
we detect, what is broken, what is unproven, and what should we do next?*

This module is that composition — and only that. It **recomputes nothing**:

* per-technique ``last_validated`` + staleness comes from
  :func:`btagent_backend.services.validation_coverage_service.build_coverage_map`
  (#118 Phase C), untouched;
* over-firing rules come from
  :func:`btagent_backend.services.noise_baseline.compute_noise_baseline` (#112),
  the same pure function ``GET /hunt/noise-baseline`` serves;
* the remaining rule states (``errored`` / ``under_firing``) are read off the
  EXISTING ``hunt_pack_runs.rule_stats`` substrate with the same precedence the
  HuntPacks view already uses client-side, so a rule's health reads identically
  on both screens;
* proposals, their review state, their telemetry outcome and their stored
  ``DataSourceMatcher`` result come from the #113 ``detection_proposals`` rows —
  the OCSF gap set is *read*, never re-matched here (the matcher runs once, at
  persist time, in ``cti_detection_service``);
* verdict counts are a tally of the persisted ``detection_validation_runs``
  verdicts.

Everything is org-scoped at the query, read-only (no flush, no commit), and
carries no cross-tenant join.

A note on "telemetry gaps"
--------------------------
Two different questions hide behind the phrase, and this panel answers both
without blurring them. Each gap row says which via ``reason`` + ``signal``:

1. **Can this rule fire at all?** The #113 ``DataSourceMatcher`` reconciles the
   OCSF event classes a rule needs against the ``ocsf_emits`` of the connectors
   the org has actually bound. Since migration ``0066_proposal_ds_gaps`` that
   output is **persisted** on ``detection_proposals``
   (``data_sources_required`` / ``data_source_gaps``), so a gap here is a stored
   fact, not an inference: nothing the org is connected to emits the telemetry
   the rule keys on. ``reason="ocsf_telemetry_gap"``, ``signal="persisted"``,
   and ``missing_ocsf_classes`` names the classes. This is the primary signal
   and it outranks the other two.

2. **Has this rule been proven against telemetry?** The pre-#501 heuristic,
   kept verbatim as the **fallback**: a rule whose backends all errored could
   not be executed against the org's telemetry at all
   (``reason="backends_errored"``), and one that was never validated has never
   been proven against it (``reason="never_validated"``). Both are
   ``signal="derived"``.

The fallback is what a row written before ``0066`` gets — its
``data_source_gaps`` is NULL, meaning *the matcher never ran*, which is not the
same claim as ``[]`` ("it ran, nothing is missing"). Collapsing those two would
turn "unknown" into "covered", so the NULL/``[]`` distinction is load-bearing
here and in the column comments. A post-``0066`` row with an empty gap set still
falls through to the derived checks, so no row loses the older signal — the new
one only takes precedence when it fires.

Every gap row is still annotated with the technique's ATT&CK ``data_sources``
for context (a name for the telemetry a human would go onboard).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_cti import DetectionProposalRow
from btagent_backend.db.models_hunt import HuntPackRunRow
from btagent_backend.db.models_mitre import MitreTechniqueRow
from btagent_backend.db.models_validation import DetectionValidationRunRow
from btagent_backend.services.noise_baseline import compute_noise_baseline
from btagent_backend.services.validation_coverage_service import (
    DEFAULT_STALE_DAYS,
    build_coverage_map,
)

logger = logging.getLogger("btagent.services.coverage_console")

# How many recent pack runs the rule-health roll-up reads (mirrors the
# noise-baseline route's default lookback).
DEFAULT_LOOKBACK_RUNS = 50
# A rule observed in at least this many runs with zero hits throughout is
# under-firing — the same floor the noise baseline and the HuntPacks view use.
UNDER_FIRING_MIN_RUNS = 3
# Defensive caps so one noisy org cannot return an unbounded payload.
MAX_BROKEN_RULES = 100
MAX_TELEMETRY_GAPS = 100
# Techniques listed inline on an action row before it just reports a count.
_ACTION_SAMPLE = 10

_FAILED = "failed"
_UNKNOWN_TACTIC = "unknown"

# Telemetry-gap reasons, worst-first. ``OCSF_GAP`` is the persisted
# DataSourceMatcher verdict (the rule cannot fire); the other two are the
# validation-derived fallback (the rule was never proven).
REASON_OCSF_GAP = "ocsf_telemetry_gap"
REASON_BACKENDS_ERRORED = "backends_errored"
REASON_NEVER_VALIDATED = "never_validated"
_REASON_ORDER = {REASON_OCSF_GAP: 0, REASON_BACKENDS_ERRORED: 1, REASON_NEVER_VALIDATED: 2}

# Provenance of a gap row: a stored matcher result vs. an inference from the
# validation blob. Surfaced so the UI never presents the weaker one as the
# stronger one.
SIGNAL_PERSISTED = "persisted"
SIGNAL_DERIVED = "derived"

# Heatmap bands. Red = never proven / proven-silent, amber = stale, green = fresh.
STATUS_SILENT_GAP = "silent_gap"
STATUS_NEVER = "never"
STATUS_STALE = "stale"
STATUS_FRESH = "fresh"

VERDICT_KINDS = ("validated", "wrong_severity", "late", "silent_gap", "errored")


# --------------------------------------------------------------------------- #
# Response models
# --------------------------------------------------------------------------- #


class TechniqueCoverageCell(BaseModel):
    """One technique in the heatmap: coverage + validation freshness."""

    technique_id: str
    name: str | None = None
    tactic: str = _UNKNOWN_TACTIC
    last_validated: datetime | None = None
    last_verdict: str | None = None
    days_since_validated: int | None = None
    stale: bool
    has_detection: bool
    # Heatmap band, precedence silent_gap > never > stale > fresh.
    status: str


class TacticColumn(BaseModel):
    """One ATT&CK tactic column of the matrix, with its band tallies."""

    tactic: str
    techniques: list[TechniqueCoverageCell] = Field(default_factory=list)
    fresh: int = 0
    stale: int = 0
    never: int = 0
    silent_gap: int = 0


class BrokenRule(BaseModel):
    """A deployed rule that is not doing its job (the #112 "dead 13%")."""

    pack_id: str
    pack_name: str
    rule_id: str
    rule_title: str
    # ``HuntRuleState`` value: over_firing | under_firing | errored.
    state: str
    runs_observed: int
    runs_hit: int
    hit_rate: float
    total_hits: int
    last_errors: int
    last_run_at: datetime | None = None


class TelemetryGap(BaseModel):
    """A technique whose detection cannot fire — or cannot be proven — today."""

    technique_id: str
    name: str | None = None
    proposal_id: str
    proposal_row_id: str
    title: str
    # ``ocsf_telemetry_gap`` (persisted: no connected connector emits a required
    # OCSF class), ``backends_errored`` (every backend failed to run the rule) or
    # ``never_validated`` (no historical-telemetry validation has ever run).
    reason: str
    # ``persisted`` (the stored #113 DataSourceMatcher verdict) or ``derived``
    # (inferred from the stored validation blob — the pre-#501 fallback).
    signal: str = SIGNAL_DERIVED
    # OCSF event classes the rule needs that NOTHING connected emits. Non-empty
    # only for ``reason="ocsf_telemetry_gap"``.
    missing_ocsf_classes: list[str] = Field(default_factory=list)
    # Connectors the matcher found that CAN supply part of the rule's telemetry.
    data_sources_required: list[str] = Field(default_factory=list)
    unavailable_backends: list[str] = Field(default_factory=list)
    available_backends: list[str] = Field(default_factory=list)
    # ATT&CK-declared data sources for the technique (context, not a decision).
    attack_data_sources: list[str] = Field(default_factory=list)


class VerdictCounts(BaseModel):
    """Validation verdicts tallied by kind across the org's run history."""

    validated: int = 0
    wrong_severity: int = 0
    late: int = 0
    silent_gap: int = 0
    errored: int = 0
    total: int = 0


class NextBestAction(BaseModel):
    """One prioritised thing to do, deep-linked to the surface that does it."""

    id: str
    # revalidate_technique | author_detection | tune_rule | review_draft
    kind: str
    title: str
    detail: str
    # 1 = most urgent. Ordering key for the list.
    priority: int
    count: int
    # Frontend route the action hands off to.
    link: str
    technique_ids: list[str] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list)


class CoverageSummary(BaseModel):
    """The headline numbers the console leads with."""

    total_techniques: int = 0
    with_detection: int = 0
    fresh: int = 0
    stale: int = 0
    never_validated: int = 0
    silent_gap: int = 0
    # MITRE matrix reference counts (mapped vs unmapped).
    mitre_total_techniques: int = 0
    mapped_techniques: int = 0
    unmapped_techniques: int = 0
    # Rule health + pipeline.
    broken_rules: int = 0
    telemetry_gaps: int = 0
    # The subset of ``telemetry_gaps`` backed by the persisted DataSourceMatcher
    # verdict (a rule that cannot fire), as opposed to the derived fallback.
    ocsf_telemetry_gaps: int = 0
    open_proposals: int = 0
    proposals_awaiting_review: int = 0
    prs_open: int = 0


class CoverageConsole(BaseModel):
    """The single composed payload behind ``GET /coverage/console``."""

    generated_at: datetime
    stale_days: int
    summary: CoverageSummary
    tactics: list[TacticColumn] = Field(default_factory=list)
    techniques: list[TechniqueCoverageCell] = Field(default_factory=list)
    broken_rules: list[BrokenRule] = Field(default_factory=list)
    telemetry_gaps: list[TelemetryGap] = Field(default_factory=list)
    verdict_counts: VerdictCounts = Field(default_factory=VerdictCounts)
    next_best_actions: list[NextBestAction] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Pure helpers (unit-testable without a DB)
# --------------------------------------------------------------------------- #


def classify_status(
    *, stale: bool, last_validated: datetime | None, last_verdict: str | None
) -> str:
    """Heatmap band for one technique.

    Precedence is worst-first so a technique that is *both* stale and known to
    have gone silent reads as the more serious of the two: a proven silent gap
    is a coverage hole, while staleness is only an unknown.
    """
    if last_verdict == STATUS_SILENT_GAP:
        return STATUS_SILENT_GAP
    if last_validated is None:
        return STATUS_NEVER
    return STATUS_STALE if stale else STATUS_FRESH


def classify_rule_state(
    *,
    last_errors: int,
    is_over_firing: bool,
    runs_observed: int,
    total_hits: int,
) -> str | None:
    """Health of one rule, or ``None`` when the rule is healthy.

    Same precedence as the HuntPacks view's client-side classifier so a rule
    never reads as ``errored`` on one screen and ``over_firing`` on the other:
    errored > over_firing > under_firing > healthy.
    """
    if last_errors > 0:
        return "errored"
    if is_over_firing:
        return "over_firing"
    if runs_observed >= UNDER_FIRING_MIN_RUNS and total_hits == 0:
        return "under_firing"
    return None


def tally_verdicts(verdict_payloads: list[list[dict[str, Any]] | None]) -> VerdictCounts:
    """Count per-technique verdicts by kind over a set of runs' ``verdicts``."""
    counts = dict.fromkeys(VERDICT_KINDS, 0)
    total = 0
    for verdicts in verdict_payloads:
        for verdict in verdicts or []:
            kind = verdict.get("verdict")
            if kind in counts:
                counts[kind] += 1
                total += 1
    return VerdictCounts(**counts, total=total)


def _backend_split(validation: dict[str, Any] | None) -> tuple[list[str], list[str]]:
    """``(unavailable, available)`` backend names from a stored validation blob."""
    unavailable: list[str] = []
    available: list[str] = []
    for entry in (validation or {}).get("backends", []) or []:
        name = entry.get("backend")
        if not name:
            continue
        (unavailable if entry.get("error") else available).append(name)
    return sorted(set(unavailable)), sorted(set(available))


def _json_str_list(value: Any) -> list[str] | None:
    """A persisted JSON list of strings, or ``None`` when the column is unset.

    ``None`` in, ``None`` out — the "matcher never ran" marker must survive
    intact, because it is what selects the derived fallback. A stored ``[]``
    comes back as ``[]`` (a real "nothing missing"), and any non-list junk is
    treated as unset rather than coerced into a claim.
    """
    if not isinstance(value, list):
        return None
    return [str(item) for item in value if isinstance(item, str) and item]


def classify_telemetry_gap(
    *,
    persisted_gaps: list[str] | None,
    validation: dict[str, Any] | None,
    unavailable_backends: list[str],
    available_backends: list[str],
) -> tuple[str, str] | None:
    """``(reason, signal)`` for one proposal, or ``None`` when it is not a gap.

    Precedence, worst-first:

    1. ``ocsf_telemetry_gap`` — the persisted DataSourceMatcher verdict says a
       required OCSF class is emitted by nothing the org has connected. The rule
       *cannot* fire, so it outranks any question of whether it was ever proven.
    2. ``backends_errored`` — a validation ran and every backend failed, so the
       rule could not be executed against the org's telemetry at all.
    3. ``never_validated`` — no historical-telemetry validation has ever run.

    (2) and (3) are the pre-#501 derived heuristic, unchanged. They still apply
    to rows whose matcher output is absent (NULL — legacy rows) *and* to rows
    whose matcher output is present but empty, so nothing that used to surface
    stops surfacing.
    """
    if persisted_gaps:
        return (REASON_OCSF_GAP, SIGNAL_PERSISTED)
    if unavailable_backends and not available_backends:
        return (REASON_BACKENDS_ERRORED, SIGNAL_DERIVED)
    if validation is None:
        return (REASON_NEVER_VALIDATED, SIGNAL_DERIVED)
    # The rule ran somewhere and its telemetry reconciles — not a gap.
    return None


# --------------------------------------------------------------------------- #
# Composition
# --------------------------------------------------------------------------- #


async def _rule_health(db: AsyncSession, *, org_id: str, lookback_runs: int) -> list[BrokenRule]:
    """Roll the org's recent pack-run history into the broken-rule list.

    Reads the same ``hunt_pack_runs.rule_stats`` substrate the noise baseline
    reads, and reuses :func:`compute_noise_baseline` verbatim for the
    over-firing set rather than re-deriving it.
    """
    rows = list(
        (
            await db.execute(
                select(HuntPackRunRow)
                .where(
                    HuntPackRunRow.org_id == org_id,
                    HuntPackRunRow.status != _FAILED,
                )
                .order_by(HuntPackRunRow.started_at.desc())
                .limit(lookback_runs)
            )
        )
        .scalars()
        .all()
    )
    if not rows:
        return []

    over_firing = {(r.pack_id, r.rule_id) for r in compute_noise_baseline(rows)}

    # Rows arrive newest-first, so the first sighting of a rule is its latest.
    agg: dict[tuple[str, str], dict[str, Any]] = {}
    for run in rows:
        for rule_id, entry in (run.rule_stats or {}).items():
            key = (run.pack_id, rule_id)
            hits = int(entry.get("hits", 0) or 0)
            state = agg.get(key)
            if state is None:
                state = {
                    "pack_name": run.pack_name,
                    "title": entry.get("title", rule_id),
                    "observed": 0,
                    "hit_runs": 0,
                    "total_hits": 0,
                    "last_errors": int(entry.get("errors", 0) or 0),
                    "last_run_at": run.started_at,
                }
                agg[key] = state
            state["observed"] += 1
            state["total_hits"] += hits
            if hits > 0:
                state["hit_runs"] += 1

    broken: list[BrokenRule] = []
    for (pack_id, rule_id), state in agg.items():
        rule_state = classify_rule_state(
            last_errors=state["last_errors"],
            is_over_firing=(pack_id, rule_id) in over_firing,
            runs_observed=state["observed"],
            total_hits=state["total_hits"],
        )
        if rule_state is None:
            continue
        observed = state["observed"]
        broken.append(
            BrokenRule(
                pack_id=pack_id,
                pack_name=state["pack_name"],
                rule_id=rule_id,
                rule_title=state["title"],
                state=rule_state,
                runs_observed=observed,
                runs_hit=state["hit_runs"],
                hit_rate=round(state["hit_runs"] / observed, 4) if observed else 0.0,
                total_hits=state["total_hits"],
                last_errors=state["last_errors"],
                last_run_at=state["last_run_at"],
            )
        )

    # Errored first (a rule that cannot run is the most broken), then the
    # loudest over-firers, then silent rules; stable by id.
    order = {"errored": 0, "over_firing": 1, "under_firing": 2}
    broken.sort(key=lambda r: (order[r.state], -r.total_hits, r.pack_id, r.rule_id))
    return broken[:MAX_BROKEN_RULES]


def _build_actions(
    *,
    cells: list[TechniqueCoverageCell],
    broken_rules: list[BrokenRule],
    telemetry_gaps: list[TelemetryGap],
    awaiting_review: int,
    awaiting_ids: list[str],
) -> list[NextBestAction]:
    """The "what should we do next" list, worst-first."""
    actions: list[NextBestAction] = []

    silent = [c.technique_id for c in cells if c.status == STATUS_SILENT_GAP]
    if silent:
        actions.append(
            NextBestAction(
                id="nba_silent_gap",
                kind="author_detection",
                title=f"{len(silent)} technique(s) fired with no rule at all",
                detail=(
                    "A validation run emulated these techniques and nothing "
                    "alerted — a proven coverage hole. Author or ship a detection."
                ),
                priority=1,
                count=len(silent),
                link="/detection-proposals",
                technique_ids=silent[:_ACTION_SAMPLE],
            )
        )

    never = [c.technique_id for c in cells if c.status == STATUS_NEVER]
    if never:
        actions.append(
            NextBestAction(
                id="nba_never_validated",
                kind="revalidate_technique",
                title=f"{len(never)} technique(s) have never been validated",
                detail=(
                    "A detection exists but has never been proven to fire. "
                    "Run a sandbox emulation to find out."
                ),
                priority=2,
                count=len(never),
                link="/detection-validation",
                technique_ids=never[:_ACTION_SAMPLE],
            )
        )

    errored_rules = [r for r in broken_rules if r.state == "errored"]
    if errored_rules:
        actions.append(
            NextBestAction(
                id="nba_errored_rules",
                kind="tune_rule",
                title=f"{len(errored_rules)} rule(s) errored on their last run",
                detail=(
                    "These rules did not execute — they are dark, not clean. "
                    "Fix the query or the backend."
                ),
                priority=2,
                count=len(errored_rules),
                link="/hunt-packs",
                rule_ids=[r.rule_id for r in errored_rules[:_ACTION_SAMPLE]],
            )
        )

    if telemetry_gaps:
        # Name the hard, stored half explicitly — "no connector emits this" and
        # "nobody has checked" need different fixes (onboard telemetry vs. run a
        # validation), and one detail line that only described the softer case
        # was part of the honesty debt #501 left behind.
        missing_classes = sorted({c for g in telemetry_gaps for c in g.missing_ocsf_classes if c})
        cannot_fire = sum(1 for g in telemetry_gaps if g.reason == REASON_OCSF_GAP)
        title = f"{len(telemetry_gaps)} detection(s) unproven against telemetry"
        detail = (
            "The rule could not be executed against the org's historical "
            "telemetry, so its coverage claim is unverified. Check the "
            "data sources it needs."
        )
        if missing_classes:
            title = f"{len(telemetry_gaps)} detection(s) cannot fire or are unproven"
            detail = (
                f"{cannot_fire} cannot fire at all: no connected connector emits "
                f"{', '.join(missing_classes[:_ACTION_SAMPLE])} — onboard that "
                "telemetry. The rest are unproven against the org's history."
            )
        actions.append(
            NextBestAction(
                id="nba_telemetry_gaps",
                kind="author_detection",
                title=title,
                detail=detail,
                priority=3,
                count=len(telemetry_gaps),
                link="/detection-proposals",
                technique_ids=[g.technique_id for g in telemetry_gaps[:_ACTION_SAMPLE]],
            )
        )

    stale = [c.technique_id for c in cells if c.status == STATUS_STALE]
    if stale:
        actions.append(
            NextBestAction(
                id="nba_stale",
                kind="revalidate_technique",
                title=f"{len(stale)} technique(s) are overdue for re-validation",
                detail="Last proven working outside the staleness horizon.",
                priority=3,
                count=len(stale),
                link="/detection-validation",
                technique_ids=stale[:_ACTION_SAMPLE],
            )
        )

    noisy_rules = [r for r in broken_rules if r.state in ("over_firing", "under_firing")]
    if noisy_rules:
        actions.append(
            NextBestAction(
                id="nba_noisy_rules",
                kind="tune_rule",
                title=f"{len(noisy_rules)} rule(s) need tuning",
                detail=(
                    "Chronic hitters drown the queue; rules that never hit are "
                    "coverage that only looks present."
                ),
                priority=4,
                count=len(noisy_rules),
                link="/hunt-packs",
                rule_ids=[r.rule_id for r in noisy_rules[:_ACTION_SAMPLE]],
            )
        )

    if awaiting_review:
        actions.append(
            NextBestAction(
                id="nba_drafts",
                kind="review_draft",
                title=f"{awaiting_review} detection draft(s) awaiting review",
                detail="Proposed rules sitting in the queue — coverage already drafted.",
                priority=4,
                count=awaiting_review,
                link="/detection-proposals",
                technique_ids=awaiting_ids[:_ACTION_SAMPLE],
            )
        )

    actions.sort(key=lambda a: (a.priority, -a.count, a.id))
    return actions


async def build_coverage_console(
    db: AsyncSession,
    *,
    org_id: str,
    stale_days: int = DEFAULT_STALE_DAYS,
    lookback_runs: int = DEFAULT_LOOKBACK_RUNS,
    now: datetime | None = None,
) -> CoverageConsole:
    """Compose the whole detection-engineering picture for one org.

    Read-only and strictly org-scoped: every query filters on ``org_id`` and
    nothing is written or flushed. ``now`` is injectable for deterministic tests
    and is threaded into the coverage map so both agree on "today".
    """
    now = now or datetime.now(UTC)

    # ---- (1) technique coverage + validation freshness (#118, reused as-is).
    entries = await build_coverage_map(db, org_id=org_id, stale_days=stale_days, now=now)

    # ---- (2) technique metadata: tactic, name, ATT&CK data sources.
    universe = [e.technique_id for e in entries]
    meta: dict[str, tuple[str, str, list[str]]] = {}
    if universe:
        for tech_id, name, tactic, data_sources in (
            await db.execute(
                select(
                    MitreTechniqueRow.id,
                    MitreTechniqueRow.name,
                    MitreTechniqueRow.tactic,
                    MitreTechniqueRow.data_sources,
                ).where(MitreTechniqueRow.id.in_(universe))
            )
        ).all():
            meta[tech_id] = (name, tactic or _UNKNOWN_TACTIC, list(data_sources or []))

    cells = [
        TechniqueCoverageCell(
            technique_id=e.technique_id,
            name=e.name or (meta.get(e.technique_id) or (None,))[0],
            tactic=(meta.get(e.technique_id) or (None, _UNKNOWN_TACTIC))[1],
            last_validated=e.last_validated,
            last_verdict=e.last_verdict,
            days_since_validated=e.days_since_validated,
            stale=e.stale,
            has_detection=e.has_detection,
            status=classify_status(
                stale=e.stale,
                last_validated=e.last_validated,
                last_verdict=e.last_verdict,
            ),
        )
        for e in entries
    ]

    # ---- (3) tactic columns for the matrix-style heatmap.
    columns: dict[str, TacticColumn] = {}
    for cell in cells:
        column = columns.setdefault(cell.tactic, TacticColumn(tactic=cell.tactic))
        column.techniques.append(cell)
        setattr(column, cell.status, getattr(column, cell.status) + 1)
    tactics = sorted(columns.values(), key=lambda c: c.tactic)

    # ---- (4) rule health (#112 noise baseline + the same run substrate).
    broken_rules = await _rule_health(db, org_id=org_id, lookback_runs=lookback_runs)

    # ---- (5) proposals: review queue, PR state, telemetry gaps (#113).
    proposals = list(
        (
            await db.execute(
                select(DetectionProposalRow).where(DetectionProposalRow.org_id == org_id)
            )
        )
        .scalars()
        .all()
    )
    awaiting_review = 0
    awaiting_ids: list[str] = []
    prs_open = 0
    telemetry_gaps: list[TelemetryGap] = []
    for row in proposals:
        if row.state == "proposed":
            awaiting_review += 1
            awaiting_ids.extend(row.technique_ids or [])
        if row.pr_outcome == "pr_opened":
            prs_open += 1

        validation = row.validation if isinstance(row.validation, dict) else None
        unavailable, available = _backend_split(validation)
        # PRIMARY signal: the persisted #113 DataSourceMatcher verdict. NULL here
        # means the matcher never ran (a row predating 0066_proposal_ds_gaps), so
        # the derived heuristic below is all we have for it — that is the
        # documented fallback, not a silent downgrade.
        persisted_gaps = _json_str_list(row.data_source_gaps)
        classified = classify_telemetry_gap(
            persisted_gaps=persisted_gaps,
            validation=validation,
            unavailable_backends=unavailable,
            available_backends=available,
        )
        if classified is None:
            continue
        reason, signal = classified
        # Only the persisted reason may name classes; the derived ones know none.
        missing_ocsf = list(persisted_gaps or []) if reason == REASON_OCSF_GAP else []
        supplying = _json_str_list(row.data_sources_required) or []
        # One gap row per technique the rule claims to cover.
        for technique_id in row.technique_ids or []:
            technique_meta = meta.get(technique_id)
            telemetry_gaps.append(
                TelemetryGap(
                    technique_id=technique_id,
                    name=technique_meta[0] if technique_meta else None,
                    proposal_id=row.proposal_id,
                    proposal_row_id=row.id,
                    title=row.title,
                    reason=reason,
                    signal=signal,
                    missing_ocsf_classes=list(missing_ocsf),
                    data_sources_required=supplying,
                    unavailable_backends=unavailable,
                    available_backends=available,
                    attack_data_sources=technique_meta[2] if technique_meta else [],
                )
            )
    # Worst-first: a rule nothing can feed, then one no backend could run, then
    # one nobody has checked.
    telemetry_gaps.sort(key=lambda g: (_REASON_ORDER.get(g.reason, 9), g.technique_id))
    telemetry_gaps = telemetry_gaps[:MAX_TELEMETRY_GAPS]
    ocsf_gap_count = sum(1 for g in telemetry_gaps if g.reason == REASON_OCSF_GAP)

    # ---- (6) verdict counts across the org's validation history.
    verdict_payloads = list(
        (
            await db.execute(
                select(DetectionValidationRunRow.verdicts).where(
                    DetectionValidationRunRow.org_id == org_id
                )
            )
        )
        .scalars()
        .all()
    )
    verdict_counts = tally_verdicts(verdict_payloads)

    # ---- (7) MITRE matrix reference size (global seed data, not org data).
    mitre_total = int(
        (await db.execute(select(func.count()).select_from(MitreTechniqueRow))).scalar_one()
    )

    mapped = sum(1 for c in cells if c.has_detection)
    summary = CoverageSummary(
        total_techniques=len(cells),
        with_detection=mapped,
        fresh=sum(1 for c in cells if c.status == STATUS_FRESH),
        stale=sum(1 for c in cells if c.status == STATUS_STALE),
        never_validated=sum(1 for c in cells if c.status == STATUS_NEVER),
        silent_gap=sum(1 for c in cells if c.status == STATUS_SILENT_GAP),
        mitre_total_techniques=mitre_total,
        mapped_techniques=mapped,
        unmapped_techniques=max(mitre_total - mapped, 0),
        broken_rules=len(broken_rules),
        telemetry_gaps=len(telemetry_gaps),
        ocsf_telemetry_gaps=ocsf_gap_count,
        open_proposals=len(proposals),
        proposals_awaiting_review=awaiting_review,
        prs_open=prs_open,
    )

    console = CoverageConsole(
        generated_at=now,
        stale_days=stale_days,
        summary=summary,
        tactics=tactics,
        techniques=cells,
        broken_rules=broken_rules,
        telemetry_gaps=telemetry_gaps,
        verdict_counts=verdict_counts,
        next_best_actions=_build_actions(
            cells=cells,
            broken_rules=broken_rules,
            telemetry_gaps=telemetry_gaps,
            awaiting_review=awaiting_review,
            awaiting_ids=sorted(set(awaiting_ids)),
        ),
    )
    logger.info(
        "coverage console built (org=%s): %d technique(s), %d broken rule(s), "
        "%d telemetry gap(s) (%d persisted OCSF), %d action(s)",
        org_id,
        len(cells),
        len(broken_rules),
        len(telemetry_gaps),
        ocsf_gap_count,
        len(console.next_best_actions),
    )
    return console


__all__ = [
    "BrokenRule",
    "CoverageConsole",
    "CoverageSummary",
    "DEFAULT_LOOKBACK_RUNS",
    "NextBestAction",
    "REASON_BACKENDS_ERRORED",
    "REASON_NEVER_VALIDATED",
    "REASON_OCSF_GAP",
    "SIGNAL_DERIVED",
    "SIGNAL_PERSISTED",
    "TacticColumn",
    "TechniqueCoverageCell",
    "TelemetryGap",
    "VerdictCounts",
    "build_coverage_console",
    "classify_rule_state",
    "classify_status",
    "classify_telemetry_gap",
    "tally_verdicts",
]
