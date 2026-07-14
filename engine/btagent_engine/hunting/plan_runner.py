"""HuntPlan executor: compiled runbook queries -> engine integration nodes (#120 Phase C).

``run_plan(plan, ctx)`` executes every per-backend query on every
``TTPRunbookEntry`` of a compiled :class:`~btagent_shared.types.hunt.HuntPlan`
through the *existing* engine integration nodes (Splunk / Sentinel / Elastic /
CrowdStrike — all honouring ``BTAGENT_MOCK_CONNECTORS``), returning raw hits
as in-memory :class:`PlanHit` objects.

The shape deliberately mirrors :mod:`btagent_engine.hunting.runner` (the #112
Sigma pack executor) and reuses its event flatten / entity-extraction helpers:
failures are isolated per TTP per backend — an unreachable backend or an
unsupported query target yields an ``error`` entry and the rest of the plan
still runs. Unlike the pack runner there is no transpile step: QuerySynth
already emitted native per-backend query strings at compile time.

This module is deliberately persistence-free — no DB, no findings tables.
The backend's ``hunt_plan_service.execute_plan_and_ingest`` converts each
``PlanHit`` into a ``HuntFinding`` (source/domain ``cross_investigation``)
via ``hunt_triage_service.record_finding``.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from btagent_shared.types.hunt import Backend, HuntPlan, TTPRunbookEntry
from btagent_shared.utils.ids import generate_id
from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.hunting.runner import (
    _ELASTIC_DEFAULT_INDEX,
    _SUMMARY_KEYS,
    SigmaHitEntity,
    _extract_entities,
    _extract_observable,
    _first_str,
    _flatten,
)
from btagent_engine.integrations.crowdstrike import (
    CrowdStrikeEventSearchInput,
    CrowdStrikeEventSearchNode,
)
from btagent_engine.integrations.elastic import ElasticSearchInput, ElasticSearchNode
from btagent_engine.integrations.sentinel import SentinelKQLQueryInput, SentinelKQLQueryNode
from btagent_engine.integrations.splunk import SplunkSearchInput, SplunkSearchNode
from btagent_engine.node import NodeContext

logger = logging.getLogger("btagent.engine.hunting.plan_runner")


# ---------------------------------------------------------------------------
# Hit / result models
# ---------------------------------------------------------------------------


class PlanHit(BaseModel):
    """One raw event matched by a hunt-plan query, normalised for ingest."""

    model_config = ConfigDict(extra="forbid")

    source_run_id: str
    plan_id: str
    ttp_id: str
    ttp_name: str = ""
    backend: str
    entities: list[SigmaHitEntity] = Field(default_factory=list)
    observable: str | None = None
    observable_type: str | None = None
    summary: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)


class PlanBackendResult(BaseModel):
    """Outcome of one query on one backend for one TTP entry."""

    model_config = ConfigDict(extra="forbid")

    backend: str
    query: str
    hit_count: int = 0
    error: str | None = None


class TTPRunResult(BaseModel):
    """All backend outcomes + hits for a single TTP runbook entry."""

    model_config = ConfigDict(extra="forbid")

    ttp_id: str
    ttp_name: str = ""
    backend_results: list[PlanBackendResult] = Field(default_factory=list)
    hits: list[PlanHit] = Field(default_factory=list)


class PlanRunResult(BaseModel):
    """Full outcome of executing a HuntPlan's runbook."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    plan_id: str
    org_id: str
    started_at: datetime
    completed_at: datetime | None = None
    ttp_results: list[TTPRunResult] = Field(default_factory=list)

    @property
    def all_hits(self) -> list[PlanHit]:
        return [hit for ttp in self.ttp_results for hit in ttp.hits]

    @property
    def error_count(self) -> int:
        return sum(
            1 for ttp in self.ttp_results for br in ttp.backend_results if br.error is not None
        )


# ---------------------------------------------------------------------------
# Per-backend execution adapters (existing engine integration nodes)
# ---------------------------------------------------------------------------


async def _run_splunk(
    query: str, ctx: NodeContext, lookback_hours: int, max_hits: int
) -> list[dict[str, Any]]:
    out = await SplunkSearchNode().run(
        SplunkSearchInput(query=query, earliest_time=f"-{lookback_hours}h", max_count=max_hits),
        ctx,
    )
    return out.events


async def _run_sentinel(
    query: str, ctx: NodeContext, lookback_hours: int, max_hits: int
) -> list[dict[str, Any]]:
    out = await SentinelKQLQueryNode().run(
        SentinelKQLQueryInput(query=query, timespan_hours=lookback_hours),
        ctx,
    )
    return out.rows[:max_hits]


async def _run_elastic(
    query: str, ctx: NodeContext, lookback_hours: int, max_hits: int
) -> list[dict[str, Any]]:
    # Plans carry no Sigma logsource, so the category->index mapping the pack
    # runner uses doesn't apply; query the default index with the same
    # timestamp bound + newest-first cap discipline (Codex #198).
    bounded_query = {
        "bool": {
            "filter": [
                {"query_string": {"query": query}},
                {"range": {"@timestamp": {"gte": f"now-{lookback_hours}h"}}},
            ]
        }
    }
    out = await ElasticSearchNode().run(
        ElasticSearchInput(index=_ELASTIC_DEFAULT_INDEX, query=bounded_query, size=max_hits),
        ctx,
    )
    return [
        {**hit.get("_source", {}), "_index": hit.get("_index"), "_id": hit.get("_id")}
        for hit in out.hits
    ]


async def _run_crowdstrike(
    query: str, ctx: NodeContext, lookback_hours: int, max_hits: int
) -> list[dict[str, Any]]:
    out = await CrowdStrikeEventSearchNode().run(
        CrowdStrikeEventSearchInput(
            query=query, lookback_hours=lookback_hours, max_events=max_hits
        ),
        ctx,
    )
    return out.events


_BACKEND_ADAPTERS = {
    Backend.SPLUNK: _run_splunk,
    Backend.SENTINEL: _run_sentinel,
    Backend.ELASTIC: _run_elastic,
    Backend.CROWDSTRIKE: _run_crowdstrike,
}


def _to_hit(
    raw: dict[str, Any],
    *,
    entry: TTPRunbookEntry,
    plan: HuntPlan,
    backend: Backend,
    run_id: str,
) -> PlanHit:
    flat = _flatten(raw)
    observable, observable_type = _extract_observable(flat)
    summary = _first_str(flat, _SUMMARY_KEYS) or f"{entry.ttp_id} hit on {backend.value}"
    return PlanHit(
        source_run_id=run_id,
        plan_id=plan.id,
        ttp_id=entry.ttp_id,
        ttp_name=entry.ttp_name,
        backend=backend.value,
        entities=_extract_entities(flat),
        observable=observable,
        observable_type=observable_type,
        summary=summary[:1024],
        raw=raw,
    )


# ---------------------------------------------------------------------------
# run_plan
# ---------------------------------------------------------------------------


async def run_plan(
    plan: HuntPlan,
    ctx: NodeContext,
    *,
    lookback_hours: int = 24,
    max_hits_per_query: int = 100,
) -> PlanRunResult:
    """Execute every runbook query of ``plan`` and collect normalised hits.

    Per TTP entry per backend: run the QuerySynth-emitted native query
    through the matching integration node and convert raw events to
    :class:`PlanHit`. An execution failure — or a query targeting a backend
    with no execution adapter (e.g. ``sigma``/``defender``) — is captured as
    that :class:`PlanBackendResult.error` and never aborts the rest of the
    plan. Entries whose ``queries`` are empty (a degraded compile) simply
    contribute no results.
    """
    run_id = generate_id("hrun")
    result = PlanRunResult(
        run_id=run_id,
        plan_id=plan.id,
        org_id=plan.org_id,
        started_at=datetime.now(UTC),
    )

    for entry in plan.ttp_entries:
        ttp_result = TTPRunResult(ttp_id=entry.ttp_id, ttp_name=entry.ttp_name)
        for backend, query in entry.queries.items():
            if not query.query.strip():
                continue  # degraded compile left an empty query for this backend
            adapter = _BACKEND_ADAPTERS.get(backend)
            if adapter is None:
                ttp_result.backend_results.append(
                    PlanBackendResult(
                        backend=backend.value,
                        query=query.query,
                        error=f"no execution adapter for backend '{backend.value}'",
                    )
                )
                continue
            try:
                raw_events = await adapter(query.query, ctx, lookback_hours, max_hits_per_query)
            except Exception as exc:  # one unreachable backend must not kill the run
                logger.warning(
                    "plan execution failed: plan=%s ttp=%s backend=%s: %s",
                    plan.id,
                    entry.ttp_id,
                    backend.value,
                    exc,
                )
                ttp_result.backend_results.append(
                    PlanBackendResult(
                        backend=backend.value,
                        query=query.query,
                        error=f"execution failed: {exc}",
                    )
                )
                continue

            hits = [
                _to_hit(raw, entry=entry, plan=plan, backend=backend, run_id=run_id)
                for raw in raw_events
            ]
            ttp_result.hits.extend(hits)
            ttp_result.backend_results.append(
                PlanBackendResult(backend=backend.value, query=query.query, hit_count=len(hits))
            )
        result.ttp_results.append(ttp_result)

    result.completed_at = datetime.now(UTC)
    return result
