"""Detection-validation core logic — simulation-fixture slice (#118).

Pure-logic module: no DB, no network, no LLM, no ``time.time()``.
All inputs are injected so the replay loop is fully deterministic and
coverage diffs are reviewable in CI.

Public API
----------
replay_scenario(scenario, hunt_runner_callable)
    Feed each ``SimulatedAttackEvent`` in a ``SimulationScenario`` through
    an injected callable (the real engine runner or a test stub).  Returns
    a list of ``(event, hits)`` pairs in the same order as the scenario's
    events.

compute_coverage(replay_results, expected_techniques)
    Walk the replay results and compute per-technique ``CoverageResult``
    objects.  Pure comparison: counts fires, missed-but-expected, and
    unexpected-fire cases.

coverage_gaps(report)
    Extract the list of technique IDs where at least one expected-to-fire
    event was missed — the "gap" list the Detection Validation Agent surfaces
    to analysts.

build_report(run_id, scenarios, replay_results_per_scenario, generated_at)
    Assemble a full ``ValidationReport`` from a list of scenarios and their
    corresponding replay results.

Callables injected
------------------
``hunt_runner_callable`` must match the type::

    async def runner(event_dict: dict[str, Any]) -> list[SigmaHit]: ...

Tests supply a stub; the backend service wires the real engine runner.

Design notes
------------
* The replay loop iterates ``scenario.events`` in order and calls the runner
  once per event.  Order is stable (no sorting, no randomness) so per-event
  index is reproducible.
* ``compute_coverage`` groups by ``technique_id`` and never modifies the
  input.  Each ``CoverageResult`` is built fresh from the accumulated
  evidence so the computation is idempotent.
* ``coverage_gaps`` is a one-liner filter over the report to keep it
  composable with future severity-weighted gap ranking.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from btagent_shared.types.detection_validation import (
    CoverageResult,
    SimulatedAttackEvent,
    SimulationScenario,
    ValidationReport,
    ValidationSummary,
)

# ---------------------------------------------------------------------------
# Protocol for the injected runner callable
# ---------------------------------------------------------------------------


@runtime_checkable
class HuntRunnerCallable(Protocol):
    """Async callable: raw event dict → list of SigmaHit-shaped dicts.

    The concrete type of each hit is intentionally left as ``dict[str, Any]``
    so this module stays free of the pySigma-heavy engine import.  The only
    field the validation logic reads from a hit is ``rule_id`` (used for
    ``rules_expected_but_missed`` tracking).

    The engine runner and the test stubs both satisfy this protocol.
    """

    async def __call__(self, event_dict: dict[str, Any]) -> list[dict[str, Any]]: ...


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


async def replay_scenario(
    scenario: SimulationScenario,
    hunt_runner_callable: HuntRunnerCallable,
) -> list[tuple[SimulatedAttackEvent, list[dict[str, Any]]]]:
    """Replay all events in *scenario* through *hunt_runner_callable*.

    Each event is fed to the runner exactly once, in order.  The result is
    a list of ``(event, hits)`` pairs — ``hits`` is whatever the runner
    returned (empty list when no rules fired).

    The loop is intentionally sequential (not gathered) to keep replay order
    stable and to avoid introducing non-determinism via concurrent execution.

    Parameters
    ----------
    scenario:
        The ``SimulationScenario`` whose events to replay.
    hunt_runner_callable:
        An async callable matching :class:`HuntRunnerCallable`.  In
        production this wraps the engine runner; in tests it is a stub.

    Returns
    -------
    list[tuple[SimulatedAttackEvent, list[dict[str, Any]]]]
        Parallel list to ``scenario.events`` — index *i* holds the event
        and the hits it produced.
    """
    results: list[tuple[SimulatedAttackEvent, list[dict[str, Any]]]] = []
    for event in scenario.events:
        hits = await hunt_runner_callable(event.source_event_dict)
        results.append((event, hits))
    return results


def compute_coverage(
    replay_results: list[tuple[SimulatedAttackEvent, list[dict[str, Any]]]],
    expected_techniques: list[str],
) -> list[CoverageResult]:
    """Compute per-technique ``CoverageResult`` from replay output.

    Parameters
    ----------
    replay_results:
        Output of :func:`replay_scenario` — list of ``(event, hits)`` pairs.
    expected_techniques:
        All technique IDs that *should* appear in the report (even those with
        zero simulated events, so gaps are visible).  Typically
        ``scenario.technique_ids``.

    Returns
    -------
    list[CoverageResult]
        One entry per technique in ``expected_techniques``, plus any
        additional techniques encountered in the replay results that were not
        in ``expected_techniques``.  Order: expected_techniques first (in
        their original order), then extras sorted for determinism.
    """
    # Accumulate per-technique evidence from replay.
    tech_total: dict[str, int] = defaultdict(int)
    tech_detected: dict[str, int] = defaultdict(int)
    tech_missed: dict[str, int] = defaultdict(int)
    tech_rules_fired: dict[str, set[str]] = defaultdict(set)
    tech_expected_rule_ids: dict[str, set[str]] = defaultdict(set)
    tech_fired_rule_ids: dict[str, set[str]] = defaultdict(set)
    tech_false_positives: dict[str, int] = defaultdict(int)

    for event, hits in replay_results:
        tid = event.technique_id
        tech_total[tid] += 1

        fired_rule_ids = {h["rule_id"] for h in hits if "rule_id" in h}
        tech_rules_fired[tid].update(fired_rule_ids)
        tech_fired_rule_ids[tid].update(fired_rule_ids)

        if event.expected_rule_id:
            tech_expected_rule_ids[tid].add(event.expected_rule_id)

        # Codex #215: a benign-control hit (``expected_to_fire=False`` + any
        # rule fires) is a FALSE POSITIVE — track separately so it can't
        # inflate ``detected`` / ``detected_pct``. A benign control with no
        # hits is the desired outcome and contributes to neither bucket.
        if not event.expected_to_fire:
            if hits:
                tech_false_positives[tid] += 1
            continue

        # ``expected_to_fire=True`` from here on. An event with a pinned
        # ``expected_rule_id`` is detected ONLY when THAT rule fired — a
        # different (broad) rule lighting up is not the same signal and
        # would mask the targeted validation gap (Codex #215 P1).
        if event.expected_rule_id:
            if event.expected_rule_id in fired_rule_ids:
                tech_detected[tid] += 1
            else:
                tech_missed[tid] += 1
        elif hits:
            tech_detected[tid] += 1
        else:
            tech_missed[tid] += 1

    # Determine the full set of techniques to report on.
    seen_techniques = set(tech_total.keys())
    ordered: list[str] = list(dict.fromkeys(expected_techniques))  # preserve order, dedupe
    for extra in sorted(seen_techniques - set(ordered)):
        ordered.append(extra)

    results: list[CoverageResult] = []
    for tid in ordered:
        expected_rule_ids = tech_expected_rule_ids[tid]
        fired = tech_fired_rule_ids[tid]
        missed_expected_rules = sorted(expected_rule_ids - fired)

        results.append(
            CoverageResult(
                technique_id=tid,
                total_simulated=tech_total[tid],
                detected=tech_detected[tid],
                missed=tech_missed[tid],
                false_positives=tech_false_positives[tid],
                rules_fired=sorted(tech_rules_fired[tid]),
                rules_expected_but_missed=missed_expected_rules,
            )
        )

    return results


def coverage_gaps(report: ValidationReport) -> list[str]:
    """Return technique IDs where at least one expected event was missed.

    This is the "gap list" the Detection Validation Agent surfaces to
    analysts: techniques for which we have a simulation but no detection.
    It reads directly from the report's ``summary.gaps`` field (which
    :func:`build_report` computes from :func:`compute_coverage` output) so
    it can be called post-hoc without re-running the coverage logic.

    Parameters
    ----------
    report:
        A ``ValidationReport`` built by :func:`build_report`.

    Returns
    -------
    list[str]
        Technique IDs with ``missed > 0``, in their report order.
    """
    return list(report.summary.gaps)


def build_report(
    run_id: str,
    scenarios: list[SimulationScenario],
    replay_results_per_scenario: list[list[tuple[SimulatedAttackEvent, list[dict[str, Any]]]]],
    generated_at: datetime,
) -> ValidationReport:
    """Assemble a ``ValidationReport`` from scenarios and their replay results.

    Parameters
    ----------
    run_id:
        Stable identifier for this validation run (caller-supplied so it can
        be a ULID, a git SHA, a timestamp string, or a fixed string in tests).
    scenarios:
        The ``SimulationScenario`` objects that were replayed (in order).
    replay_results_per_scenario:
        Parallel list to ``scenarios`` — index *i* is the return value of
        ``replay_scenario(scenarios[i], runner)``.
    generated_at:
        Report timestamp.  Caller-supplied (never ``datetime.now()`` inside
        this function) to keep the report deterministic.

    Returns
    -------
    ValidationReport
    """
    # Collect all expected techniques across all scenarios.
    expected_techniques: list[str] = []
    seen: set[str] = set()
    for scenario in scenarios:
        for tid in scenario.technique_ids:
            if tid not in seen:
                expected_techniques.append(tid)
                seen.add(tid)

    # Flatten all replay pairs from all scenarios for coverage computation.
    all_pairs: list[tuple[SimulatedAttackEvent, list[dict[str, Any]]]] = []
    for pairs in replay_results_per_scenario:
        all_pairs.extend(pairs)

    coverage = compute_coverage(all_pairs, expected_techniques)

    # Build summary.
    total_expected_fire = sum(1 for event, _hits in all_pairs if event.expected_to_fire)
    total_detected = sum(cr.detected for cr in coverage)
    if total_expected_fire > 0:
        detected_pct = round(100.0 * total_detected / total_expected_fire, 2)
    else:
        detected_pct = 100.0

    gaps = [cr.technique_id for cr in coverage if cr.missed > 0]

    summary = ValidationSummary(
        detected_pct=detected_pct,
        total_techniques=len(coverage),
        gaps=gaps,
    )

    return ValidationReport(
        run_id=run_id,
        scenarios_run=len(scenarios),
        coverage_by_technique=coverage,
        summary=summary,
        generated_at=generated_at,
    )
