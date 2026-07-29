"""Noise baseline over hunt-pack run history (#112).

``hunt_pack_runs.rule_stats`` records per-rule hit volumes for every pack
execution — "the substrate the future noise baselines read". This module is
that reader, in **both directions**:

* *over-firing* (:func:`compute_noise_baseline`) — rules that hit on (nearly)
  every run of their pack, which in practice means the rule is matching
  baseline activity rather than an incident: advisory suppression candidates.
* *under-firing* (:func:`compute_under_firing`) — rules with a zero-hit record
  across a whole 60-day window: coverage that only *looks* present. A rule
  that has never fired in two months is either mis-scoped, pointed at
  telemetry the org does not send, or genuinely dead — either way it is a
  detection-engineering review item, not a suppression candidate.

Advisory only, by design: nothing here writes a suppression rule or retires a
detection. The analyst reviews the lists (``GET /hunt/noise-baseline``, which
carries both, and ``GET /hunt/under-firing``) and acts through the existing
suppression / detection APIs — the same HITL posture as the rest of the hunt
inbox (a machine may propose; only an analyst decides).

Semantics (shared by both directions):

* Rules are tracked **per pack** — the same ``rule_id`` in two packs is two
  candidates (different query contexts, different noise profiles).
* A rule's ``runs_observed`` counts only runs whose ``rule_stats`` mention
  it, so a rule added in pack v2 isn't penalised for v1 runs it wasn't in.
* ``failed`` runs carry no per-rule signal and are excluded entirely;
  ``completed_with_errors`` runs still contribute (their successful
  rule×backend executions are real observations).
* A rule whose most recent observation *errored* is **dark, not silent**: it
  is reported as ``errored`` by the rule-state surfaces and is excluded from
  the under-firing list, matching the precedence the HuntPacks view and the
  Coverage Console already use (errored > over_firing > under_firing).
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_hunt import HuntPackRunRow

_FAILED = "failed"

# A rule must have gone this long with zero hits to count as under-firing.
UNDER_FIRING_WINDOW_DAYS = 60
# …across at least this many runs, so a pack that ran twice last week cannot
# put its whole rule set on the review list. Same floor the HuntPacks view and
# the Coverage Console use.
UNDER_FIRING_MIN_RUNS = 3
# Defensive cap on how many runs the under-firing window query reads.
UNDER_FIRING_MAX_RUNS = 500


class _RunLike(Protocol):
    """The slice of :class:`HuntPackRunRow` the pure analysis reads."""

    pack_id: str
    pack_name: str
    rule_stats: dict[str, Any]
    status: str
    started_at: datetime


def _aware(value: datetime) -> datetime:
    """UTC-normalise a timestamp (SQLite hands back naive datetimes)."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


class NoisyRule(BaseModel):
    """One chronically-hitting rule — an advisory suppression candidate."""

    pack_id: str
    pack_name: str
    rule_id: str
    rule_title: str
    runs_observed: int
    runs_hit: int
    hit_rate: float
    total_hits: int
    avg_hits_per_run: float
    last_hit_at: datetime | None


class UnderFiringRule(BaseModel):
    """One rule with a zero-hit record across the whole window."""

    pack_id: str
    pack_name: str
    rule_id: str
    rule_title: str
    # Runs of its pack (inside the window) whose rule_stats mention the rule.
    runs_observed: int
    # Always 0 — carried so the row reads the same shape as ``NoisyRule``.
    total_hits: int = 0
    first_observed_at: datetime | None = None
    last_observed_at: datetime | None = None
    # Whole days between the first and last silent observation in the window.
    days_silent: int = 0
    window_days: int = UNDER_FIRING_WINDOW_DAYS


class UnderFiringReport(BaseModel):
    """Advisory list of silent rules — a detection-engineering review queue."""

    items: list[UnderFiringRule] = Field(default_factory=list)
    runs_analyzed: int = 0
    window_days: int = UNDER_FIRING_WINDOW_DAYS
    min_runs: int = UNDER_FIRING_MIN_RUNS


class NoiseBaseline(BaseModel):
    items: list[NoisyRule]
    runs_analyzed: int
    min_runs: int
    hit_rate_threshold: float
    # The mirror-image advisory (#112 Phase C): rules that have NOT fired at
    # all inside ``under_firing_window_days``. Carried on the same review
    # payload the Noisy Rules surface already reads, so both halves of "is this
    # rule doing its job?" arrive together. Empty when analysis is skipped.
    under_firing: list[UnderFiringRule] = Field(default_factory=list)
    under_firing_window_days: int = UNDER_FIRING_WINDOW_DAYS


def compute_noise_baseline(
    runs: Iterable[_RunLike],
    *,
    min_runs: int = 3,
    hit_rate_threshold: float = 0.8,
) -> list[NoisyRule]:
    """Pure per-(pack, rule) hit-rate analysis over run history rows.

    A rule qualifies when it was observed in at least ``min_runs`` runs of
    its pack, hit in at least ``hit_rate_threshold`` of them, and produced
    at least one hit overall. Sorted noisiest-first (hit rate, then volume).
    """
    stats: dict[tuple[str, str], dict[str, Any]] = {}
    for run in runs:
        if run.status == _FAILED:
            continue
        for rule_id, entry in (run.rule_stats or {}).items():
            hits = int(entry.get("hits", 0) or 0)
            key = (run.pack_id, rule_id)
            agg = stats.setdefault(
                key,
                {
                    "pack_name": run.pack_name,
                    "title": entry.get("title", rule_id),
                    "observed": 0,
                    "hit_runs": 0,
                    "total_hits": 0,
                    "last_hit_at": None,
                },
            )
            agg["observed"] += 1
            if hits > 0:
                agg["hit_runs"] += 1
                agg["total_hits"] += hits
                if agg["last_hit_at"] is None or run.started_at > agg["last_hit_at"]:
                    agg["last_hit_at"] = run.started_at

    noisy: list[NoisyRule] = []
    for (pack_id, rule_id), agg in stats.items():
        if agg["observed"] < min_runs or agg["total_hits"] == 0:
            continue
        hit_rate = agg["hit_runs"] / agg["observed"]
        if hit_rate < hit_rate_threshold:
            continue
        noisy.append(
            NoisyRule(
                pack_id=pack_id,
                pack_name=agg["pack_name"],
                rule_id=rule_id,
                rule_title=agg["title"],
                runs_observed=agg["observed"],
                runs_hit=agg["hit_runs"],
                hit_rate=round(hit_rate, 4),
                total_hits=agg["total_hits"],
                avg_hits_per_run=round(agg["total_hits"] / agg["observed"], 2),
                last_hit_at=agg["last_hit_at"],
            )
        )
    noisy.sort(key=lambda r: (-r.hit_rate, -r.total_hits, r.pack_id, r.rule_id))
    return noisy


def compute_under_firing(
    runs: Iterable[_RunLike],
    *,
    window_days: int = UNDER_FIRING_WINDOW_DAYS,
    min_runs: int = UNDER_FIRING_MIN_RUNS,
    now: datetime | None = None,
) -> list[UnderFiringRule]:
    """Pure per-(pack, rule) silence analysis over run history rows.

    The mirror image of :func:`compute_noise_baseline`: a rule qualifies when,
    across the runs of its pack inside the last ``window_days``, it was
    observed at least ``min_runs`` times and produced **zero** hits in every
    one of them — and its most recent observation did not error (an errored
    rule is dark, not silent; see the module docstring's precedence note).

    ``now`` is injectable so tests are deterministic. Sorted
    longest-silent-first, then by observation count.
    """
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=window_days)

    stats: dict[tuple[str, str], dict[str, Any]] = {}
    for run in runs:
        if run.status == _FAILED:
            continue
        started = _aware(run.started_at)
        if started < cutoff:
            continue
        for rule_id, entry in (run.rule_stats or {}).items():
            key = (run.pack_id, rule_id)
            agg = stats.setdefault(
                key,
                {
                    "pack_name": run.pack_name,
                    "title": entry.get("title", rule_id),
                    "observed": 0,
                    "total_hits": 0,
                    "first_at": started,
                    "last_at": started,
                    # Errors on the rule's most recent observation in the window.
                    "last_errors": 0,
                },
            )
            agg["observed"] += 1
            agg["total_hits"] += int(entry.get("hits", 0) or 0)
            if started < agg["first_at"]:
                agg["first_at"] = started
            if started >= agg["last_at"]:
                agg["last_at"] = started
                agg["last_errors"] = int(entry.get("errors", 0) or 0)

    silent: list[UnderFiringRule] = []
    for (pack_id, rule_id), agg in stats.items():
        if agg["observed"] < min_runs or agg["total_hits"] > 0 or agg["last_errors"] > 0:
            continue
        silent.append(
            UnderFiringRule(
                pack_id=pack_id,
                pack_name=agg["pack_name"],
                rule_id=rule_id,
                rule_title=agg["title"],
                runs_observed=agg["observed"],
                total_hits=0,
                first_observed_at=agg["first_at"],
                last_observed_at=agg["last_at"],
                days_silent=max((agg["last_at"] - agg["first_at"]).days, 0),
                window_days=window_days,
            )
        )
    silent.sort(key=lambda r: (-r.days_silent, -r.runs_observed, r.pack_id, r.rule_id))
    return silent


async def under_firing(
    db: AsyncSession,
    *,
    org_id: str,
    window_days: int = UNDER_FIRING_WINDOW_DAYS,
    min_runs: int = UNDER_FIRING_MIN_RUNS,
    max_runs: int = UNDER_FIRING_MAX_RUNS,
    now: datetime | None = None,
) -> UnderFiringReport:
    """Rules with a zero-hit record over the org's last ``window_days``.

    Org-scoped at the query and read-only. ``failed`` runs are excluded (they
    carry no per-rule signal), and the window is applied in SQL so a long-lived
    org only reads the runs it needs.
    """
    now = now or datetime.now(UTC)
    result = await db.execute(
        select(HuntPackRunRow)
        .where(
            HuntPackRunRow.org_id == org_id,
            HuntPackRunRow.status != _FAILED,
            HuntPackRunRow.started_at >= now - timedelta(days=window_days),
        )
        .order_by(HuntPackRunRow.started_at.desc())
        .limit(max_runs)
    )
    rows = list(result.scalars().all())
    return UnderFiringReport(
        items=compute_under_firing(rows, window_days=window_days, min_runs=min_runs, now=now),
        runs_analyzed=len(rows),
        window_days=window_days,
        min_runs=min_runs,
    )


async def noise_baseline(
    db: AsyncSession,
    *,
    org_id: str,
    lookback_runs: int = 50,
    min_runs: int = 3,
    hit_rate_threshold: float = 0.8,
    include_under_firing: bool = True,
    under_firing_window_days: int = UNDER_FIRING_WINDOW_DAYS,
    now: datetime | None = None,
) -> NoiseBaseline:
    """Analyse the org's most recent ``lookback_runs`` pack executions.

    Returns both halves of the advisory: the chronically-hitting rules and —
    unless ``include_under_firing`` is off — the rules that have gone silent
    for a whole ``under_firing_window_days`` window (a separate, date-bounded
    query, since "the last 50 runs" and "the last 60 days" are different
    questions).
    """
    result = await db.execute(
        select(HuntPackRunRow)
        .where(
            HuntPackRunRow.org_id == org_id,
            HuntPackRunRow.status != _FAILED,
        )
        .order_by(HuntPackRunRow.started_at.desc())
        .limit(lookback_runs)
    )
    rows = list(result.scalars().all())
    silent: list[UnderFiringRule] = []
    if include_under_firing:
        report = await under_firing(
            db, org_id=org_id, window_days=under_firing_window_days, now=now
        )
        silent = report.items
    return NoiseBaseline(
        items=compute_noise_baseline(
            rows, min_runs=min_runs, hit_rate_threshold=hit_rate_threshold
        ),
        runs_analyzed=len(rows),
        min_runs=min_runs,
        hit_rate_threshold=hit_rate_threshold,
        under_firing=silent,
        under_firing_window_days=under_firing_window_days,
    )
