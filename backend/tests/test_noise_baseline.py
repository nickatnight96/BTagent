"""Tests for the #112 noise baseline (chronically-hitting pack rules).

Pure analysis over ``rule_stats`` history plus the read-only advisory API.
The shared test org accumulates pack-run rows across files, so API
assertions scope by per-test unique pack/rule ids — never absolute counts.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from btagent_shared.utils.ids import generate_id
from conftest import auth_header

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_hunt import HuntPackRunRow
from btagent_backend.services.noise_baseline import (
    NEVER_RUN_WINDOW_DAYS,
    compute_never_run,
    compute_noise_baseline,
)

_T0 = datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)


def _run(
    pack_id: str,
    rule_stats: dict,
    *,
    status: str = "completed",
    at: datetime = _T0,
    pack_name: str = "Windows Baseline",
    rules_not_run: tuple[str, ...] = (),
):
    return SimpleNamespace(
        pack_id=pack_id,
        pack_name=pack_name,
        rule_stats=rule_stats,
        status=status,
        started_at=at,
        rules_not_run=list(rules_not_run),
    )


def _stats(hits: int, title: str = "Encoded PowerShell") -> dict:
    return {"title": title, "hits": hits, "errors": 0}


# --------------------------------------------------------------------------- #
# Pure analysis
# --------------------------------------------------------------------------- #


def test_chronic_rule_is_flagged_with_correct_stats():
    runs = [
        _run("pack_a", {"r1": _stats(5)}, at=_T0),
        _run("pack_a", {"r1": _stats(3)}, at=_T0 + timedelta(days=1)),
        _run("pack_a", {"r1": _stats(0)}, at=_T0 + timedelta(days=2)),
        _run("pack_a", {"r1": _stats(4)}, at=_T0 + timedelta(days=3)),
    ]
    noisy = compute_noise_baseline(runs, min_runs=3, hit_rate_threshold=0.7)
    assert len(noisy) == 1
    r = noisy[0]
    assert (r.pack_id, r.rule_id) == ("pack_a", "r1")
    assert r.runs_observed == 4
    assert r.runs_hit == 3
    assert r.hit_rate == 0.75
    assert r.total_hits == 12
    assert r.avg_hits_per_run == 3.0
    assert r.last_hit_at == _T0 + timedelta(days=3)  # the 0-hit run doesn't advance it


def test_low_hit_rate_and_underobserved_rules_are_excluded():
    runs = [
        # r_low hits 1 of 4 runs — under threshold.
        _run("pack_a", {"r_low": _stats(9)}, at=_T0),
        _run("pack_a", {"r_low": _stats(0)}, at=_T0 + timedelta(days=1)),
        _run("pack_a", {"r_low": _stats(0)}, at=_T0 + timedelta(days=2)),
        _run("pack_a", {"r_low": _stats(0)}, at=_T0 + timedelta(days=3)),
        # r_new hits 100% but only 2 observations — under min_runs.
        _run("pack_b", {"r_new": _stats(2)}, at=_T0),
        _run("pack_b", {"r_new": _stats(2)}, at=_T0 + timedelta(days=1)),
    ]
    assert compute_noise_baseline(runs, min_runs=3, hit_rate_threshold=0.8) == []


def test_zero_hit_rules_and_failed_runs_are_ignored():
    runs = [
        # Rule present in every run but never hits — not noise, just quiet.
        _run("pack_a", {"r_quiet": _stats(0)}, at=_T0),
        _run("pack_a", {"r_quiet": _stats(0)}, at=_T0 + timedelta(days=1)),
        _run("pack_a", {"r_quiet": _stats(0)}, at=_T0 + timedelta(days=2)),
        # A failed run carries no signal even if rule_stats has entries.
        _run("pack_a", {"r_quiet": _stats(99)}, status="failed", at=_T0 + timedelta(days=3)),
    ]
    assert compute_noise_baseline(runs, min_runs=3, hit_rate_threshold=0.5) == []


def test_same_rule_id_tracked_per_pack():
    mk = lambda pack, hits, day: _run(pack, {"r1": _stats(hits)}, at=_T0 + timedelta(days=day))  # noqa: E731
    runs = [
        # In pack_a, r1 hits every run; in pack_b it never does.
        mk("pack_a", 2, 0),
        mk("pack_a", 2, 1),
        mk("pack_a", 2, 2),
        mk("pack_b", 0, 0),
        mk("pack_b", 0, 1),
        mk("pack_b", 0, 2),
    ]
    noisy = compute_noise_baseline(runs, min_runs=3, hit_rate_threshold=0.8)
    assert [(r.pack_id, r.rule_id) for r in noisy] == [("pack_a", "r1")]


def test_sorted_noisiest_first():
    runs = []
    for day in range(4):
        runs.append(
            _run(
                "pack_a",
                {
                    "r_always": _stats(10),
                    "r_mostly": _stats(1 if day < 3 else 0),
                },
                at=_T0 + timedelta(days=day),
            )
        )
    noisy = compute_noise_baseline(runs, min_runs=3, hit_rate_threshold=0.7)
    assert [r.rule_id for r in noisy] == ["r_always", "r_mostly"]


# --------------------------------------------------------------------------- #
# Never-run (the third direction: rules the cap/deadline skipped every sweep)
# --------------------------------------------------------------------------- #

_NEVER_RUN_NOW = _T0 + timedelta(days=10)


def _skipped(pack_id: str, rule_ids: tuple[str, ...], *, day: int, **kw):
    """A truncated sweep that executed nothing and skipped ``rule_ids``."""
    return _run(pack_id, {}, at=_T0 + timedelta(days=day), rules_not_run=rule_ids, **kw)


def test_chronically_skipped_rule_is_flagged_with_correct_stats():
    runs = [_skipped("pack_a", ("r_dark",), day=d) for d in (0, 4, 9)]
    dark = compute_never_run(runs, now=_NEVER_RUN_NOW)
    assert len(dark) == 1
    r = dark[0]
    assert (r.pack_id, r.rule_id) == ("pack_a", "r_dark")
    assert r.runs_skipped == 3
    assert r.first_skipped_at == _T0
    assert r.last_skipped_at == _T0 + timedelta(days=9)
    assert r.days_dark == 9
    assert r.window_days == NEVER_RUN_WINDOW_DAYS


def test_a_rule_that_executed_even_once_is_not_never_run():
    """The disjointness guarantee: one execution makes it the hit-rate lists' problem.

    Otherwise a rule could be reported as never-run *and* over-firing at the
    same time, and the analyst would get contradictory advice about it.
    """
    runs = [_skipped("pack_a", ("r1",), day=d) for d in (0, 4, 9)]
    runs.append(_run("pack_a", {"r1": _stats(3)}, at=_T0 + timedelta(days=5)))
    assert compute_never_run(runs, now=_NEVER_RUN_NOW) == []


def test_execution_in_an_older_run_still_disqualifies():
    """The executed set is built across the whole window before any verdict.

    Rows arrive newest-first from the query, so an implementation that decided
    run by run would emit this rule after seeing three skips and only later
    learn it had executed. Ordering must not change the answer.
    """
    runs = [
        _skipped("pack_a", ("r1",), day=9),
        _skipped("pack_a", ("r1",), day=6),
        _skipped("pack_a", ("r1",), day=3),
        # Oldest row, read last: the one execution in the window.
        _run("pack_a", {"r1": _stats(0)}, at=_T0),
    ]
    assert compute_never_run(runs, now=_NEVER_RUN_NOW) == []


def test_a_single_capped_sweep_is_not_a_blind_spot():
    runs = [
        _skipped("pack_a", ("r1",), day=9),
        _run("pack_a", {"r2": _stats(1)}, at=_T0 + timedelta(days=4)),
        _run("pack_a", {"r2": _stats(1)}, at=_T0),
    ]
    assert compute_never_run(runs, now=_NEVER_RUN_NOW) == []


def test_incomplete_runs_do_not_count_as_skips():
    """A failed/abandoned sweep skipped rules because it broke, not because of a cap."""
    runs = [
        _skipped("pack_a", ("r1",), day=0, status="failed"),
        _skipped("pack_a", ("r1",), day=4, status="abandoned"),
        _skipped("pack_a", ("r1",), day=9, status="failed"),
    ]
    assert compute_never_run(runs, now=_NEVER_RUN_NOW) == []


def test_completed_with_errors_still_counts_as_a_skip():
    """A partially-errored sweep still reached (and declined to run) the tail."""
    runs = [_skipped("pack_a", ("r1",), day=d, status="completed_with_errors") for d in (0, 4, 9)]
    assert [r.rule_id for r in compute_never_run(runs, now=_NEVER_RUN_NOW)] == ["r1"]


def test_skips_outside_the_window_are_ignored():
    old = _NEVER_RUN_NOW - timedelta(days=NEVER_RUN_WINDOW_DAYS + 5)
    runs = [
        _run("pack_a", {}, at=old, rules_not_run=("r1",)),
        _run("pack_a", {}, at=old + timedelta(days=1), rules_not_run=("r1",)),
        _skipped("pack_a", ("r1",), day=9),
    ]
    assert compute_never_run(runs, now=_NEVER_RUN_NOW) == []


def test_never_run_is_tracked_per_pack():
    runs = [_skipped("pack_a", ("shared",), day=d) for d in (0, 4, 9)]
    runs += [_skipped("pack_b", ("shared",), day=d) for d in (0, 4)]
    # pack_b only reached two skips, so only pack_a's copy qualifies.
    dark = compute_never_run(runs, now=_NEVER_RUN_NOW)
    assert [(r.pack_id, r.rule_id) for r in dark] == [("pack_a", "shared")]


def test_sorted_longest_dark_first():
    runs = [_skipped("pack_a", ("r_recent",), day=d) for d in (7, 8, 9)]  # 2 days of darkness
    runs += [_skipped("pack_a", ("r_old",), day=d) for d in (0, 5, 9)]  # 9 days
    dark = compute_never_run(runs, now=_NEVER_RUN_NOW)
    assert [r.rule_id for r in dark] == ["r_old", "r_recent"]


def test_a_pack_that_runs_every_rule_reports_nothing():
    """Guard the guard — the analysis is not flagging on presence alone."""
    runs = [
        _run("pack_a", {"r1": _stats(0), "r2": _stats(2)}, at=_T0 + timedelta(days=d))
        for d in (0, 4, 9)
    ]
    assert compute_never_run(runs, now=_NEVER_RUN_NOW) == []


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #


async def _seed_run(
    db_session,
    pack_id: str,
    rule_stats: dict,
    *,
    at: datetime,
    rules_not_run: tuple[str, ...] = (),
) -> None:
    db_session.add(
        HuntPackRunRow(
            id=generate_id("hpr"),
            org_id=DEFAULT_ORG_ID,
            run_id=generate_id("hrun"),
            pack_id=pack_id,
            pack_name="API seeded pack",
            backends=["splunk"],
            rule_stats=rule_stats,
            hit_count=sum(int(v.get("hits", 0)) for v in rule_stats.values()),
            error_count=0,
            findings_created=0,
            status="completed",
            truncated=bool(rules_not_run),
            rules_not_run=list(rules_not_run),
            started_at=at,
        )
    )
    await db_session.commit()


async def test_noise_baseline_api(client, analyst_token, sample_user, db_session):
    pack_id = generate_id("pack")
    rule_id = generate_id("rule")
    for day in range(3):
        await _seed_run(
            db_session,
            pack_id,
            {rule_id: {"title": "Chronic beacon", "hits": 7, "errors": 0}},
            at=_T0 + timedelta(days=day),
        )

    resp = await client.get(
        "/api/v1/hunt/noise-baseline?min_runs=3&hit_rate_threshold=0.8&lookback_runs=500",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["min_runs"] == 3
    assert data["runs_analyzed"] >= 3
    mine = [i for i in data["items"] if i["pack_id"] == pack_id]
    assert len(mine) == 1
    assert mine[0]["rule_id"] == rule_id
    assert mine[0]["rule_title"] == "Chronic beacon"
    assert mine[0]["hit_rate"] == 1.0
    assert mine[0]["total_hits"] == 21


async def test_noise_baseline_carries_never_run(client, analyst_token, sample_user, db_session):
    """A chronically-capped pack surfaces its skipped tail on the combined payload.

    Seeded relative to *now* rather than the file's fixed ``_T0``, because
    unlike the over-firing analysis this one is window-bounded and would go
    quiet once ``_T0`` aged past 60 days.
    """
    now = datetime.now(UTC)
    pack_id = generate_id("pack")
    ran_id = generate_id("rule")
    dark_id = generate_id("rule")
    for day in (12, 6, 1):
        await _seed_run(
            db_session,
            pack_id,
            {ran_id: {"title": "Executed rule", "hits": 0, "errors": 0}},
            at=now - timedelta(days=day),
            rules_not_run=(dark_id,),
        )

    resp = await client.get(
        "/api/v1/hunt/noise-baseline?lookback_runs=500",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["never_run_window_days"] == NEVER_RUN_WINDOW_DAYS

    mine = [i for i in data["never_run"] if i["pack_id"] == pack_id]
    assert len(mine) == 1
    assert mine[0]["rule_id"] == dark_id
    assert mine[0]["runs_skipped"] == 3
    assert mine[0]["days_dark"] == 11

    # The rule that *did* run is under-firing (observed 3×, never hit), not
    # never-run — the two lists carve up the pack rather than overlapping.
    assert dark_id not in {i["rule_id"] for i in data["under_firing"]}
    assert ran_id in {i["rule_id"] for i in data["under_firing"] if i["pack_id"] == pack_id}


async def test_noise_baseline_requires_auth(client):
    resp = await client.get("/api/v1/hunt/noise-baseline")
    assert resp.status_code in (401, 403)
