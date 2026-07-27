"""Fire a HuntPlan's ``correlation_rules`` + ``post_actions`` on ingest (#99).

Until now a plan's :class:`~btagent_shared.types.hunt.CorrelationRule` /
:class:`~btagent_shared.types.hunt.PostHuntAction` list was *data only* — it
rode the compiled plan and rendered into the markdown export, but nothing ever
fired it. Hits landed in the triage inbox via
:func:`hunt_triage_service.record_finding` and stopped there.

This executor is invoked from the finding-ingest path
(:func:`hunt_plan_service.execute_plan_and_ingest`) once a run's hits are
recorded. It turns the plan's declared rules into real actions:

* **spawn_investigation** — a hit spawns an Investigation from the run's hit
  findings (via :func:`hunt_triage_service.promote_to_investigation`, which
  flips the findings to ``PROMOTED`` and seeds the case with their observables
  + technique mapping). Any hit is enough.
* **escalate_to_ir** — 3+ *distinct correlated* TTPs hitting in one run raises
  the spawned investigation to an IR: severity → ``critical``, an
  ``escalated_to_ir`` config flag + escalation record, and a hash-chain audit
  event.

**Autonomy-aware / HITL.** The plan carries the analyst's
:class:`~btagent_shared.types.config.AutonomyLevel`. At ``L0``/``L1`` the agent
may not act unattended, so the executor *defers*: it records the correlation as
a HITL-pending audit event and takes no destructive action. At ``L2`` and above
it fires inline (the spawned investigation is itself created ``pending``, so a
human still reviews it — matching L2 "agent executes, human reviews").

Per the codebase convention this service **flushes, never commits** — the route
/ arq job owns the single commit — and it is *best-effort*: the caller wraps it
so a correlation-executor fault can never sink an ingest that already landed
findings.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

from btagent_shared.types.config import AutonomyLevel
from btagent_shared.types.enums import AuditCategory, AuditOutcome, Severity
from btagent_shared.types.hunt import HuntFindingState, HuntPlan
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_hunt import HuntFindingRow
from btagent_backend.services import hunt_triage_service
from btagent_backend.services.audit_trail import AuditTrail

logger = logging.getLogger("btagent.services.hunt_correlation")

# Distinct correlated TTP hits in one run that escalate the spawned
# investigation to an IR. Mirrors the ``corr_multi_ttp_escalate_ir`` default
# rule's trigger text so the plan's declared threshold and the executor's
# evaluated threshold never drift.
_ESCALATE_TO_IR_MIN_TTPS = 3

# Autonomy levels at which the agent may act unattended. L0/L1 require a human
# in the loop, so the executor defers instead of firing.
_AUTO_AUTONOMY = frozenset(
    {
        AutonomyLevel.L2_SUPERVISED,
        AutonomyLevel.L3_AUTONOMOUS,
        AutonomyLevel.L4_FULL_AUTO,
    }
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class CorrelationOutcome:
    """What the executor did, for logging / caller bookkeeping / tests."""

    spawned_investigation_id: str | None = None
    escalated_to_ir: bool = False
    deferred_hitl: bool = False
    correlated_ttps: list[str] = field(default_factory=list)
    fired_rule_ids: list[str] = field(default_factory=list)


def _plan_target(plan: HuntPlan) -> str:
    """Short human label for the hunt's subject (actors / TTPs / plan id)."""
    return ", ".join(plan.input.adversaries + plan.input.ttps) or plan.id


async def fire_plan_correlations(
    db: AsyncSession,
    *,
    plan: HuntPlan,
    org_id: str,
    hit_findings: list[HuntFindingRow],
    run_id: str,
    actor: str | None = None,
) -> CorrelationOutcome:
    """Evaluate + fire the plan's correlation rules against a run's hits.

    Args:
        plan: The compiled plan whose ``correlation_rules`` drive the executor.
            A plan with no ``spawn_investigation`` / ``escalate_to_ir`` rule
            fires nothing (the feature is data-driven).
        org_id: Tenant scope for every write.
        hit_findings: The finding rows just recorded for this run's hits.
            Suppressed rows are ignored (a suppressed hit is expected noise).
        run_id: The plan-run id (for provenance in the escalation record).
        actor: Audit/assignment actor; defaults to the plan initiator.

    Returns:
        A :class:`CorrelationOutcome` describing what fired. Flushes, never
        commits.
    """
    outcome = CorrelationOutcome()

    # Only unsuppressed hits correlate — a suppressed finding is acknowledged
    # noise and must not spawn a case.
    live_hits = [fr for fr in hit_findings if fr.state != HuntFindingState.SUPPRESSED.value]
    if not live_hits:
        return outcome

    spawn_rules = [r for r in plan.correlation_rules if r.action == "spawn_investigation"]
    escalate_rules = [r for r in plan.correlation_rules if r.action == "escalate_to_ir"]
    if not spawn_rules and not escalate_rules:
        return outcome  # plan opted out of both — nothing to fire

    correlated_ttps = sorted({t for fr in live_hits for t in (fr.technique_ids or [])})
    outcome.correlated_ttps = correlated_ttps

    try:
        autonomy = AutonomyLevel(plan.input.autonomy_level)
    except (ValueError, TypeError):
        autonomy = AutonomyLevel.L2_SUPERVISED

    escalate = bool(escalate_rules) and len(correlated_ttps) >= _ESCALATE_TO_IR_MIN_TTPS
    actor = actor or plan.input.initiated_by or "hunt-correlation-executor"

    # HITL gate: low-autonomy plans record intent but don't act unattended.
    if autonomy not in _AUTO_AUTONOMY:
        outcome.deferred_hitl = True
        outcome.fired_rule_ids = [r.id for r in spawn_rules + (escalate_rules if escalate else [])]
        await AuditTrail(db).record(
            org_id=org_id,
            actor=actor,
            category=AuditCategory.HUNT,
            action="correlation_deferred_hitl",
            resource=f"hunt_plan:{plan.id}",
            outcome=AuditOutcome.SUCCESS,
            details={
                "org_id": org_id,
                "plan_id": plan.id,
                "run_id": run_id,
                "autonomy_level": autonomy.value,
                "correlated_ttps": correlated_ttps,
                "would_escalate_to_ir": escalate,
                "hunt_finding_ids": [fr.id for fr in live_hits],
            },
        )
        await db.flush()
        logger.info(
            "hunt correlation deferred to HITL (autonomy=%s) for plan %s: %d hit(s), ttps=%s",
            autonomy.value,
            plan.id,
            len(live_hits),
            correlated_ttps,
        )
        return outcome

    # escalate_to_ir needs an investigation to escalate, so spawn when either a
    # spawn rule is present or the escalation threshold is met.
    if not spawn_rules and not escalate:
        return outcome

    target = _plan_target(plan)
    # Auto-spawned correlation cases land *unassigned* — the plan initiator is
    # often a system/scheduler id with no user row (FK), and an analyst claims
    # the case from the queue. ``actor`` still attributes the audit trail.
    inv, _promoted = await hunt_triage_service.promote_to_investigation(
        db,
        org_id=org_id,
        finding_ids=[fr.id for fr in live_hits],
        title=f"Hunt correlation: {target}",
        assigned_to=None,
        actor=actor,
    )
    outcome.spawned_investigation_id = inv.id
    outcome.fired_rule_ids.extend(r.id for r in spawn_rules)

    if escalate:
        inv.severity = Severity.CRITICAL.value
        cfg = dict(inv.config or {})
        cfg["escalated_to_ir"] = True
        cfg["ir_escalation"] = {
            "reason": (f"{len(correlated_ttps)} distinct correlated TTP hits in hunt run {run_id}"),
            "correlated_ttps": correlated_ttps,
            "plan_id": plan.id,
            "run_id": run_id,
        }
        inv.config = cfg
        inv.updated_at = _utcnow()
        outcome.escalated_to_ir = True
        outcome.fired_rule_ids.extend(r.id for r in escalate_rules)
        await AuditTrail(db).record(
            org_id=org_id,
            actor=actor,
            category=AuditCategory.HUNT,
            action="escalate_to_ir",
            resource=f"investigation:{inv.id}",
            outcome=AuditOutcome.SUCCESS,
            details={
                "org_id": org_id,
                "plan_id": plan.id,
                "run_id": run_id,
                "correlated_ttps": correlated_ttps,
                "severity": Severity.CRITICAL.value,
            },
        )
        await db.flush()

    logger.info(
        "hunt correlation fired for plan %s: investigation=%s escalated_to_ir=%s ttps=%s",
        plan.id,
        outcome.spawned_investigation_id,
        outcome.escalated_to_ir,
        correlated_ttps,
    )
    return outcome
