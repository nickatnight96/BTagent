"""Tests for #99 Task C — the correlation / post-action executor.

A compiled HuntPlan's ``correlation_rules`` used to be data-only. This suite
proves they now FIRE from the finding-ingest path:

* a hit spawns an Investigation (``spawn_investigation``);
* 3+ distinct correlated TTP hits escalate that investigation to IR
  (``escalate_to_ir``: severity → critical + an ``escalated_to_ir`` config
  record);
* the executor is autonomy-aware — an ``L1`` plan defers to HITL and spawns
  nothing.

All rows go through the rollback-per-test ``db_session`` under a dedicated org
(``generate_id("org")``), so investigation-count assertions are isolated from
the shared session DB per the isolation rule.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from btagent_shared.types.config import AutonomyLevel
from btagent_shared.types.hunt import (
    Backend,
    CorrelationRule,
    HuntDomain,
    HuntInput,
    HuntPlan,
    HuntSource,
    Query,
    TTPRunbookEntry,
)
from btagent_shared.utils.ids import generate_id
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import InvestigationRow, OrganizationRow
from btagent_backend.db.models_pattern import HuntPlanRow
from btagent_backend.services import (
    hunt_correlation_service,
    hunt_plan_service,
    hunt_triage_service,
)


@pytest.fixture(autouse=True)
def _force_mock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")


_SIGMA = "title: X\ndetection:\n  sel: {}\n  condition: sel\n"


def _default_rules() -> list[CorrelationRule]:
    return [
        CorrelationRule(
            id="corr_hit_spawn_investigation",
            description="hit spawns investigation",
            trigger="1+ hit",
            action="spawn_investigation",
        ),
        CorrelationRule(
            id="corr_multi_ttp_escalate_ir",
            description="3+ distinct TTPs escalate to IR",
            trigger="3+ distinct TTPs hit",
            action="escalate_to_ir",
        ),
    ]


def _plan(org_id: str, ttp_ids: list[str], *, autonomy: str = "L2") -> HuntPlan:
    return HuntPlan(
        id=generate_id("hunt"),
        org_id=org_id,
        input=HuntInput(
            ttps=ttp_ids,
            initiated_by="usr_pattern_scan",
            autonomy_level=AutonomyLevel(autonomy),
        ),
        ttp_entries=[
            TTPRunbookEntry(
                ttp_id=t,
                ttp_name=t,
                rationale="r",
                behavioral_description="b",
                queries={Backend.SIGMA: Query(backend=Backend.SIGMA, query=_SIGMA)},
            )
            for t in ttp_ids
        ],
        correlation_rules=_default_rules(),
    )


def _fake_run_plan(ttp_ids: list[str]):
    """A ``run_plan`` stub returning exactly one hit per TTP in ``ttp_ids``."""

    async def _run(plan, ctx, *, lookback_hours=24, max_hits_per_query=100):
        from btagent_engine.hunting.plan_runner import (
            PlanBackendResult,
            PlanHit,
            PlanRunResult,
            TTPRunResult,
        )

        now = datetime.now(UTC)
        run_id = generate_id("hrun")
        return PlanRunResult(
            run_id=run_id,
            plan_id=plan.id,
            org_id=ctx.org_id,
            started_at=now,
            completed_at=now,
            ttp_results=[
                TTPRunResult(
                    ttp_id=t,
                    ttp_name=t,
                    backend_results=[PlanBackendResult(backend="sigma", query="q", hit_count=1)],
                    hits=[
                        PlanHit(
                            source_run_id=run_id,
                            plan_id=plan.id,
                            ttp_id=t,
                            ttp_name=t,
                            backend="sigma",
                            summary=f"hit for {t}",
                            raw={"host": "alice-pc"},
                        )
                    ],
                )
                for t in ttp_ids
            ],
        )

    return _run


async def _seed_org(db: AsyncSession) -> str:
    org_id = generate_id("org")
    db.add(OrganizationRow(id=org_id, name="corr org", created_at=datetime.now(UTC)))
    await db.flush()
    return org_id


async def _seed_ready_plan(db: AsyncSession, plan: HuntPlan) -> str:
    now = datetime.now(UTC)
    db.add(
        HuntPlanRow(
            id=plan.id,
            org_id=plan.org_id,
            proposal_id=None,
            status="ready",
            plan=plan.model_dump(mode="json"),
            error="",
            created_at=now,
            updated_at=now,
        )
    )
    await db.flush()
    return plan.id


async def _investigations(db: AsyncSession, org_id: str) -> list[InvestigationRow]:
    return list(
        (await db.execute(select(InvestigationRow).where(InvestigationRow.org_id == org_id)))
        .scalars()
        .all()
    )


# --------------------------------------------------------------------------- #
# spawn_investigation on a hit
# --------------------------------------------------------------------------- #


async def test_hit_spawns_investigation(db_session: AsyncSession, monkeypatch) -> None:
    org_id = await _seed_org(db_session)
    plan = _plan(org_id, ["T1059.001"])
    plan_id = await _seed_ready_plan(db_session, plan)
    monkeypatch.setattr(
        "btagent_engine.hunting.plan_runner.run_plan", _fake_run_plan(["T1059.001"])
    )

    _, findings_created = await hunt_plan_service.execute_plan_and_ingest(
        db_session, plan_row_id=plan_id
    )
    assert findings_created == 1

    invs = await _investigations(db_session, org_id)
    assert len(invs) == 1
    inv = invs[0]
    assert inv.title.startswith("Hunt correlation:")
    assert inv.assigned_to is None  # auto-spawned cases are unassigned
    # A single TTP is below the escalation threshold — not IR.
    assert (inv.config or {}).get("escalated_to_ir") in (None, False)
    assert inv.severity != "critical"


# --------------------------------------------------------------------------- #
# escalate_to_ir on 3+ distinct correlated TTP hits
# --------------------------------------------------------------------------- #


async def test_three_distinct_ttp_hits_escalate_to_ir(
    db_session: AsyncSession, monkeypatch
) -> None:
    org_id = await _seed_org(db_session)
    ttps = ["T1059.001", "T1078.004", "T1566.001"]
    plan = _plan(org_id, ttps)
    plan_id = await _seed_ready_plan(db_session, plan)
    monkeypatch.setattr("btagent_engine.hunting.plan_runner.run_plan", _fake_run_plan(ttps))

    _, findings_created = await hunt_plan_service.execute_plan_and_ingest(
        db_session, plan_row_id=plan_id
    )
    assert findings_created == 3

    invs = await _investigations(db_session, org_id)
    assert len(invs) == 1
    inv = invs[0]
    assert inv.severity == "critical"
    assert inv.config["escalated_to_ir"] is True
    assert set(inv.config["ir_escalation"]["correlated_ttps"]) == set(ttps)
    assert inv.config["ir_escalation"]["plan_id"] == plan.id


# --------------------------------------------------------------------------- #
# Autonomy / HITL awareness
# --------------------------------------------------------------------------- #


async def test_low_autonomy_defers_to_hitl(db_session: AsyncSession) -> None:
    """An L1 plan records the correlation but spawns nothing (HITL gate)."""
    org_id = await _seed_org(db_session)
    ttps = ["T1059.001", "T1078.004", "T1566.001"]
    plan = _plan(org_id, ttps, autonomy="L1")

    # Record three hit findings directly, then run the executor.
    hit_rows = []
    for t in ttps:
        hit_rows.append(
            await hunt_triage_service.record_finding(
                db_session,
                org_id=org_id,
                source=HuntSource.CROSS_INVESTIGATION.value,
                domain=HuntDomain.CROSS_INVESTIGATION.value,
                title=f"hit {t}",
                technique_ids=[t],
            )
        )

    outcome = await hunt_correlation_service.fire_plan_correlations(
        db_session,
        plan=plan,
        org_id=org_id,
        hit_findings=hit_rows,
        run_id=generate_id("hrun"),
    )

    assert outcome.deferred_hitl is True
    assert outcome.spawned_investigation_id is None
    assert outcome.escalated_to_ir is False
    # Nothing spawned in the dedicated org.
    assert await _investigations(db_session, org_id) == []


async def test_executor_noop_without_correlation_rules(db_session: AsyncSession) -> None:
    """A plan with no spawn/escalate rules fires nothing even on a hit."""
    org_id = await _seed_org(db_session)
    plan = _plan(org_id, ["T1059.001"])
    plan.correlation_rules = []  # opt out

    hit = await hunt_triage_service.record_finding(
        db_session,
        org_id=org_id,
        source=HuntSource.CROSS_INVESTIGATION.value,
        domain=HuntDomain.CROSS_INVESTIGATION.value,
        title="hit",
        technique_ids=["T1059.001"],
    )
    outcome = await hunt_correlation_service.fire_plan_correlations(
        db_session,
        plan=plan,
        org_id=org_id,
        hit_findings=[hit],
        run_id=generate_id("hrun"),
    )
    assert outcome.spawned_investigation_id is None
    assert await _investigations(db_session, org_id) == []
