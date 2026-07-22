"""Noise baseline over hunt-pack run history (#112).

``hunt_pack_runs.rule_stats`` records per-rule hit volumes for every pack
execution — "the substrate the future noise baselines read". This module is
that reader: it identifies rules that hit on (nearly) every run of their
pack, which in practice means the rule is matching baseline activity rather
than an incident, and surfaces them as **advisory suppression candidates**.

Advisory only, by design: nothing here writes a suppression rule. The
analyst reviews the list (``GET /hunt/noise-baseline``) and acts through
the existing suppression API — the same HITL posture as the rest of the
hunt inbox (a machine may propose what to ignore; only an analyst decides).

Semantics:

* Rules are tracked **per pack** — the same ``rule_id`` in two packs is two
  candidates (different query contexts, different noise profiles).
* A rule's ``runs_observed`` counts only runs whose ``rule_stats`` mention
  it, so a rule added in pack v2 isn't penalised for v1 runs it wasn't in.
* ``failed`` runs carry no per-rule signal and are excluded entirely;
  ``completed_with_errors`` runs still contribute (their successful
  rule×backend executions are real observations).
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any, Protocol

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_hunt import HuntPackRunRow

_FAILED = "failed"


class _RunLike(Protocol):
    """The slice of :class:`HuntPackRunRow` the pure analysis reads."""

    pack_id: str
    pack_name: str
    rule_stats: dict[str, Any]
    status: str
    started_at: datetime


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


class NoiseBaseline(BaseModel):
    items: list[NoisyRule]
    runs_analyzed: int
    min_runs: int
    hit_rate_threshold: float


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


async def noise_baseline(
    db: AsyncSession,
    *,
    org_id: str,
    lookback_runs: int = 50,
    min_runs: int = 3,
    hit_rate_threshold: float = 0.8,
) -> NoiseBaseline:
    """Analyse the org's most recent ``lookback_runs`` pack executions."""
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
    return NoiseBaseline(
        items=compute_noise_baseline(
            rows, min_runs=min_runs, hit_rate_threshold=hit_rate_threshold
        ),
        runs_analyzed=len(rows),
        min_runs=min_runs,
        hit_rate_threshold=hit_rate_threshold,
    )
