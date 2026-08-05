"""Noise baseline over hunt-pack run history (#112).

``hunt_pack_runs.rule_stats`` records per-rule hit volumes for every pack
execution — "the substrate the future noise baselines read". This module is
that reader, in **three directions**:

* *over-firing* (:func:`compute_noise_baseline`) — rules that hit on (nearly)
  every run of their pack, which in practice means the rule is matching
  baseline activity rather than an incident: advisory suppression candidates.
* *under-firing* (:func:`compute_under_firing`) — rules with a zero-hit record
  across a whole 60-day window: coverage that only *looks* present. A rule
  that has never fired in two months is either mis-scoped, pointed at
  telemetry the org does not send, or genuinely dead — either way it is a
  detection-engineering review item, not a suppression candidate.
* *never-run* (:func:`compute_never_run`) — enabled rules that were **skipped
  by every sweep in the window** and so produced no observation at all.

That third direction reads a different column, and it exists because the
first two cannot see it *by construction*. ``rule_stats`` is written per rule
as the runner finishes it, so it contains exactly the rules that executed;
the E7 rules-per-sweep cap and per-run deadline stop the runner mid-list and
record the remainder in ``hunt_pack_runs.rules_not_run`` instead. A rule the
cap keeps skipping therefore appears in *neither* hit-rate analysis — it is
not over-firing (no hits), not under-firing (no observations), just absent.
And because the runner truncates the **tail** of ``pack.enabled_rules`` in
pack order, a pack that consistently exceeds its bound skips the *same* rules
on every sweep: the same permanent blind spot, invisible on every existing
surface. Run history shows ``rules_not_run`` for one run at a time, which
cannot distinguish "a slow tick trimmed a few rules once" from "these forty
rules have not executed in two months".

Advisory only, by design: nothing here writes a suppression rule, retires a
detection, or raises a cap. The analyst reviews the lists (``GET
/hunt/noise-baseline``, which carries all three, and ``GET
/hunt/under-firing``) and acts through the existing suppression / detection /
schedule APIs — the same HITL posture as the rest of the hunt inbox (a
machine may propose; only an analyst decides).

Semantics (shared by all three directions):

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

Deliberately **not** covered, so a clean list is not mistaken for more than it
is: a rule that executed even once inside the window is an observation and is
handed to the hit-rate analyses, so "ran in the first sweep of the window,
capped out of the forty since" is not reported as never-run. Reporting it
would require a per-run notion of "should have run", which the history rows do
not carry. The window bound is what limits the damage — over a 60-day window a
rule that has been capped out since day one drops out of ``executed`` and
surfaces normally.
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
#: An interrupted sweep, not a broken one — but still incomplete: some rules
#: never ran, so counting it as a clean sweep understates noise for exactly
#: the rules that produced nothing *because they were never executed*.
_ABANDONED = "abandoned"

#: Run statuses whose ``rule_stats`` are **not** admissible observations.
#:
#: The single definition for every surface that classifies rule health from
#: pack-run history. It is public and imported (rather than each module keeping
#: its own ``"failed"`` literal) because the surfaces are only correct while
#: they agree: a rule's state is a function of how many runs observed it, so a
#: module that admits one extra status counts observations its neighbour does
#: not and reaches a different verdict about the same rule.
#:
#: That is not hypothetical — it is what happened when ``abandoned`` was
#: introduced. ``coverage_console_service`` kept a private ``_FAILED`` and
#: silently began counting abandoned sweeps' partial stats as real
#: observations, so a pack whose worker kept restarting had its rules reported
#: as under-firing ("review this detection") while ``GET /hunt/under-firing``
#: — correctly — said nothing about them. ``test_incomplete_run_parity.py``
#: guards the agreement, in Python and in the TypeScript mirror.
INCOMPLETE_RUN_STATUSES = (_FAILED, _ABANDONED)
_INCOMPLETE = INCOMPLETE_RUN_STATUSES

# A rule must have gone this long with zero hits to count as under-firing.
UNDER_FIRING_WINDOW_DAYS = 60
# …across at least this many runs, so a pack that ran twice last week cannot
# put its whole rule set on the review list. Same floor the HuntPacks view and
# the Coverage Console use.
UNDER_FIRING_MIN_RUNS = 3
# Defensive cap on how many runs the under-firing window query reads.
UNDER_FIRING_MAX_RUNS = 500

# The never-run analysis reads the same window of runs as under-firing (it is
# the same question — "has this rule done anything for me lately?" — asked of
# the rules that never got to answer), so it shares the bounds rather than
# introducing a second set an operator would have to keep in sync.
NEVER_RUN_WINDOW_DAYS = UNDER_FIRING_WINDOW_DAYS
# A rule must have been skipped by at least this many sweeps. One capped run is
# a slow tick, not a blind spot; the floor is what makes this a *chronic*-cap
# advisory rather than a notification for every deadline overrun.
NEVER_RUN_MIN_RUNS = UNDER_FIRING_MIN_RUNS


class _RunLike(Protocol):
    """The slice of :class:`HuntPackRunRow` the pure analysis reads."""

    pack_id: str
    pack_name: str
    rule_stats: dict[str, Any]
    # E7 (migration 0069): enabled rule ids the sweep never got to, because the
    # rules-per-sweep cap or the per-run deadline stopped it early. Disjoint
    # from ``rule_stats`` by construction — the runner writes a stat entry as it
    # finishes each rule and lists the untouched remainder here.
    rules_not_run: list[str]
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


class NeverRunRule(BaseModel):
    """One enabled rule that every sweep in the window skipped."""

    pack_id: str
    pack_name: str
    rule_id: str
    # No ``rule_title``: ``rules_not_run`` carries ids only (the runner never
    # built a result object for these rules, so there is no title to copy).
    # Inventing one from the id would read like data the row does not have.
    # Runs of its pack (inside the window) that listed the rule as not run.
    runs_skipped: int
    first_skipped_at: datetime | None = None
    last_skipped_at: datetime | None = None
    # Whole days between the first and last time a sweep skipped the rule.
    days_dark: int = 0
    window_days: int = NEVER_RUN_WINDOW_DAYS


class NeverRunReport(BaseModel):
    """Advisory list of never-executed rules — a coverage-honesty queue."""

    items: list[NeverRunRule] = Field(default_factory=list)
    runs_analyzed: int = 0
    window_days: int = NEVER_RUN_WINDOW_DAYS
    min_runs: int = NEVER_RUN_MIN_RUNS


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
    # The third direction: enabled rules no sweep in the window ever executed,
    # so neither hit-rate list can see them. Carried here so one fetch answers
    # "is this rule doing its job?" for rules that hit too much, rules that hit
    # too little, and rules that never got the chance. Empty when skipped.
    never_run: list[NeverRunRule] = Field(default_factory=list)
    never_run_window_days: int = NEVER_RUN_WINDOW_DAYS


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
        if run.status in _INCOMPLETE:
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
        if run.status in _INCOMPLETE:
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


def compute_never_run(
    runs: Iterable[_RunLike],
    *,
    window_days: int = NEVER_RUN_WINDOW_DAYS,
    min_runs: int = NEVER_RUN_MIN_RUNS,
    now: datetime | None = None,
) -> list[NeverRunRule]:
    """Pure per-(pack, rule) *skip* analysis over run history rows.

    A rule qualifies when, across the runs of its pack inside the last
    ``window_days``, at least ``min_runs`` of them listed it in
    ``rules_not_run`` and **none** of them executed it (no ``rule_stats``
    entry, in any run in the window).

    That second condition is what keeps the three directions disjoint: a rule
    with even one execution is an observation, so it belongs to the hit-rate
    analyses rather than here, however often it was skipped afterwards. The
    executed set is therefore built from *every* in-window run before any
    verdict is reached, not run by run.

    ``now`` is injectable so tests are deterministic. Sorted
    longest-dark-first, then by skip count.
    """
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=window_days)

    executed: set[tuple[str, str]] = set()
    skipped: dict[tuple[str, str], dict[str, Any]] = {}
    for run in runs:
        if run.status in _INCOMPLETE:
            continue
        started = _aware(run.started_at)
        if started < cutoff:
            continue
        for rule_id in run.rule_stats or {}:
            executed.add((run.pack_id, rule_id))
        for rule_id in run.rules_not_run or []:
            key = (run.pack_id, rule_id)
            agg = skipped.setdefault(
                key,
                {
                    "pack_name": run.pack_name,
                    "skips": 0,
                    "first_at": started,
                    "last_at": started,
                },
            )
            agg["skips"] += 1
            if started < agg["first_at"]:
                agg["first_at"] = started
            if started > agg["last_at"]:
                agg["last_at"] = started

    dark: list[NeverRunRule] = []
    for (pack_id, rule_id), agg in skipped.items():
        if agg["skips"] < min_runs or (pack_id, rule_id) in executed:
            continue
        dark.append(
            NeverRunRule(
                pack_id=pack_id,
                pack_name=agg["pack_name"],
                rule_id=rule_id,
                runs_skipped=agg["skips"],
                first_skipped_at=agg["first_at"],
                last_skipped_at=agg["last_at"],
                days_dark=max((agg["last_at"] - agg["first_at"]).days, 0),
                window_days=window_days,
            )
        )
    dark.sort(key=lambda r: (-r.days_dark, -r.runs_skipped, r.pack_id, r.rule_id))
    return dark


async def _window_rows(
    db: AsyncSession,
    *,
    org_id: str,
    window_days: int,
    max_runs: int,
    now: datetime,
) -> list[HuntPackRunRow]:
    """The org's terminal pack runs inside ``window_days``, newest-first.

    Shared by the under-firing and never-run analyses: both ask about the same
    window of the same rows, so one round-trip serves both rather than two
    identical queries firing back to back on the combined payload.
    """
    result = await db.execute(
        select(HuntPackRunRow)
        .where(
            HuntPackRunRow.org_id == org_id,
            HuntPackRunRow.status.not_in(_INCOMPLETE),
            HuntPackRunRow.started_at >= now - timedelta(days=window_days),
        )
        .order_by(HuntPackRunRow.started_at.desc())
        .limit(max_runs)
    )
    return list(result.scalars().all())


async def never_run(
    db: AsyncSession,
    *,
    org_id: str,
    window_days: int = NEVER_RUN_WINDOW_DAYS,
    min_runs: int = NEVER_RUN_MIN_RUNS,
    max_runs: int = UNDER_FIRING_MAX_RUNS,
    now: datetime | None = None,
) -> NeverRunReport:
    """Enabled rules no sweep executed over the org's last ``window_days``.

    Org-scoped at the query and read-only. Incomplete runs are excluded: a
    ``failed`` or ``abandoned`` sweep did skip rules, but it skipped them
    because it broke, and counting that as evidence of a chronic cap would
    report a transient outage as a permanent blind spot.
    """
    now = now or datetime.now(UTC)
    rows = await _window_rows(
        db, org_id=org_id, window_days=window_days, max_runs=max_runs, now=now
    )
    return NeverRunReport(
        items=compute_never_run(rows, window_days=window_days, min_runs=min_runs, now=now),
        runs_analyzed=len(rows),
        window_days=window_days,
        min_runs=min_runs,
    )


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
    rows = await _window_rows(
        db, org_id=org_id, window_days=window_days, max_runs=max_runs, now=now
    )
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
    include_never_run: bool = True,
    now: datetime | None = None,
) -> NoiseBaseline:
    """Analyse the org's most recent ``lookback_runs`` pack executions.

    Returns all three directions of the advisory: the chronically-hitting
    rules, and — unless the corresponding flag is off — the rules that have
    gone silent for a whole ``under_firing_window_days`` window and the rules
    every sweep in that window skipped. The latter two share one date-bounded
    query, separate from the ``lookback_runs`` one, since "the last 50 runs"
    and "the last 60 days" are different questions.
    """
    now = now or datetime.now(UTC)
    result = await db.execute(
        select(HuntPackRunRow)
        .where(
            HuntPackRunRow.org_id == org_id,
            HuntPackRunRow.status.not_in(_INCOMPLETE),
        )
        .order_by(HuntPackRunRow.started_at.desc())
        .limit(lookback_runs)
    )
    rows = list(result.scalars().all())

    silent: list[UnderFiringRule] = []
    dark: list[NeverRunRule] = []
    if include_under_firing or include_never_run:
        window = await _window_rows(
            db,
            org_id=org_id,
            window_days=under_firing_window_days,
            max_runs=UNDER_FIRING_MAX_RUNS,
            now=now,
        )
        if include_under_firing:
            silent = compute_under_firing(window, window_days=under_firing_window_days, now=now)
        if include_never_run:
            dark = compute_never_run(window, window_days=under_firing_window_days, now=now)
    return NoiseBaseline(
        items=compute_noise_baseline(
            rows, min_runs=min_runs, hit_rate_threshold=hit_rate_threshold
        ),
        runs_analyzed=len(rows),
        min_runs=min_runs,
        hit_rate_threshold=hit_rate_threshold,
        under_firing=silent,
        under_firing_window_days=under_firing_window_days,
        never_run=dark,
        never_run_window_days=under_firing_window_days,
    )
