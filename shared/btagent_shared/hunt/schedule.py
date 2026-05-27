"""Pure scheduling-policy helpers for recurring hunts (Phase 6).

Dependency-free so the same next-run / due math is usable by the arq
worker, by tests, and (later) by the engine runtime. Nothing here talks to
a clock source it doesn't receive as an argument — callers pass ``now`` so
the logic stays deterministic and testable.
"""

from __future__ import annotations

from datetime import datetime, timedelta


def next_run_at(*, last_run: datetime | None, interval: timedelta, now: datetime) -> datetime:
    """When should a fixed-interval job next fire?

    First run (``last_run is None``) is due immediately at ``now``. Otherwise
    it's ``last_run + interval``, but never in the past relative to ``now``
    (a worker that was down catches up to a single next slot rather than
    stampeding through every missed interval).
    """
    if last_run is None:
        return now
    candidate = last_run + interval
    return candidate if candidate > now else now


def is_due(*, last_run: datetime | None, interval: timedelta, now: datetime) -> bool:
    """Has a fixed-interval job's next slot arrived?"""
    return now >= next_run_at(last_run=last_run, interval=interval, now=now)
