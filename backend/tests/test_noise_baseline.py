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
from btagent_backend.services.noise_baseline import compute_noise_baseline

_T0 = datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)


def _run(
    pack_id: str,
    rule_stats: dict,
    *,
    status: str = "completed",
    at: datetime = _T0,
    pack_name: str = "Windows Baseline",
):
    return SimpleNamespace(
        pack_id=pack_id,
        pack_name=pack_name,
        rule_stats=rule_stats,
        status=status,
        started_at=at,
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
# API
# --------------------------------------------------------------------------- #


async def _seed_run(db_session, pack_id: str, rule_stats: dict, *, at: datetime) -> None:
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


async def test_noise_baseline_requires_auth(client):
    resp = await client.get("/api/v1/hunt/noise-baseline")
    assert resp.status_code in (401, 403)
