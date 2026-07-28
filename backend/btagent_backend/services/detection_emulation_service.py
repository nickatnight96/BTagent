"""Detection-validation emulation enforcement service (#118).

This module is THE sandbox-enforcement point for adversary emulation. Every
detection-validation emulation trigger flows through
:func:`run_emulation_validation`, and it is structurally impossible to reach an
emulator from here without first passing the sandbox gate:

    evaluate_sandbox_target(request.target_env)
        │
        ├── denied  → write an AUDITED DENIED ledger row, return a 403 outcome,
        │             and NEVER dispatch the orchestrator (no emulator runs).
        │
        └── approved → write an AUDITED trigger row, THEN dispatch the
                       (sandbox-re-asserting) ValidationOrchestrator.

SAFETY — the five non-negotiables enforced here (with the layers they build on)
-------------------------------------------------------------------------------
1. **SANDBOX-ONLY.** ``run_emulation_validation`` calls
   :func:`btagent_shared.security.sandbox.evaluate_sandbox_target` first; a
   non-approved target short-circuits to :func:`_record_denial` before the
   orchestrator (and thus any emulator) is constructed. The orchestrator
   re-asserts the same guard (defence in depth).
2. **MOCK BY DEFAULT.** The default orchestrator drives mock-first MCP servers
   (``BTAGENT_MOCK_CONNECTORS`` default on); live paths raise
   ``NotImplementedError`` and the orchestrator turns that into an ``errored``
   verdict — no real technique fires.
3. **HITL-GATED.** The emulator trigger tools (``run_atomic`` / ``run_operation``)
   declare ``hitl_required=True`` in their manifests; the MCP router's policy
   gate blocks a model-driven dispatch until the HITL resume path approves.
4. **AUDITED.** Every trigger AND every denial writes a hash-chain row via
   :class:`AuditTrail` under :data:`AuditCategory.DETECTION_VALIDATION`,
   stamping actor, org_id, technique, target_env, and outcome.
5. **ORG-SCOPED.** The audit stamp and the persisted run both use the caller's
   ``org_id``; there is no cross-tenant emulation or result read.

The public function is **result-returning** (never raises for a business
denial): raising past the request boundary would roll back the denial audit row.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from btagent_shared.security.sandbox import evaluate_sandbox_target
from btagent_shared.types.detection_validation import EmulationRequest, TechniqueVerdict
from btagent_shared.types.enums import AuditCategory, AuditOutcome
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.services.audit_trail import AuditTrail

logger = logging.getLogger("btagent.services.detection_emulation")

# An injectable orchestrator entrypoint: technique request -> scored verdict.
OrchestratorRun = Callable[[EmulationRequest], Awaitable[TechniqueVerdict]]


@dataclass
class EmulationOutcome:
    """Result of an emulation-validation attempt (approved run or audited denial)."""

    approved: bool
    outcome: str  # AuditOutcome value ("success" | "denied" | "failure")
    http_status: int
    audit_id: str
    target_env: str
    technique_id: str
    reason: str = ""
    verdict: TechniqueVerdict | None = None
    detail: dict[str, Any] = field(default_factory=dict)


async def _default_orchestrator_run(request: EmulationRequest) -> TechniqueVerdict:
    """Lazily build the agents-side orchestrator (kept out of import path)."""
    from btagent_agents.validation.orchestrator import ValidationOrchestrator

    return await ValidationOrchestrator().run(request)


async def _record_denial(
    db: AsyncSession,
    *,
    actor_id: str,
    org_id: str,
    request: EmulationRequest,
    reason: str,
) -> EmulationOutcome:
    """Write an audited DENIED row for a refused (non-sandbox) trigger.

    The refusal is a first-class, hash-chained ledger fact — never a silent
    skip. Returning (not raising) lets the request commit the row before the
    403 is sent.
    """
    audit = await AuditTrail(db).record(
        actor=actor_id,
        org_id=org_id,
        category=AuditCategory.DETECTION_VALIDATION,
        action="emulation_trigger",
        resource=request.technique_id,
        outcome=AuditOutcome.DENIED,
        details={
            "actor_id": actor_id,
            "technique_id": request.technique_id,
            "target_env": request.target_env.value,
            "emulator": request.emulator.value,
            "reason": reason,
        },
    )
    logger.warning(
        "emulation DENIED org=%s actor=%s technique=%s target_env=%s reason=%s audit=%s",
        org_id,
        actor_id,
        request.technique_id,
        request.target_env.value,
        reason,
        audit.id,
    )
    return EmulationOutcome(
        approved=False,
        outcome=AuditOutcome.DENIED.value,
        http_status=403,
        audit_id=audit.id,
        target_env=request.target_env.value,
        technique_id=request.technique_id,
        reason=reason,
    )


async def run_emulation_validation(
    db: AsyncSession,
    *,
    actor_id: str,
    org_id: str,
    request: EmulationRequest,
    orchestrator_run: OrchestratorRun | None = None,
) -> EmulationOutcome:
    """Sandbox-gated, audited entry point for a detection-validation emulation.

    Returns an :class:`EmulationOutcome`. On a non-sandbox target it returns an
    audited denial WITHOUT constructing or invoking any emulator/orchestrator.
    On an approved sandbox it audits the trigger and dispatches the orchestrator.

    ``orchestrator_run`` is injectable so tests can pass a spy and assert the
    denial path never reaches it.
    """
    # ---- GUARDRAIL #1: sandbox gate — precedes every emulator dispatch path.
    decision = evaluate_sandbox_target(request.target_env)
    if decision.denied:
        return await _record_denial(
            db, actor_id=actor_id, org_id=org_id, request=request, reason=decision.reason
        )

    # ---- Approved: audit the trigger as a first-class ledger fact BEFORE run.
    trigger_audit = await AuditTrail(db).record(
        actor=actor_id,
        org_id=org_id,
        category=AuditCategory.DETECTION_VALIDATION,
        action="emulation_trigger",
        resource=request.technique_id,
        outcome=AuditOutcome.SUCCESS,
        details={
            "actor_id": actor_id,
            "technique_id": request.technique_id,
            "target_env": request.target_env.value,
            "emulator": request.emulator.value,
            "expected_severity": request.expected_severity.value,
            "latency_sla_seconds": request.latency_sla_seconds,
        },
    )
    logger.info(
        "emulation APPROVED org=%s actor=%s technique=%s target_env=%s audit=%s",
        org_id,
        actor_id,
        request.technique_id,
        request.target_env.value,
        trigger_audit.id,
    )

    runner = orchestrator_run or _default_orchestrator_run
    verdict = await runner(request)

    return EmulationOutcome(
        approved=True,
        outcome=AuditOutcome.SUCCESS.value,
        http_status=201,
        audit_id=trigger_audit.id,
        target_env=request.target_env.value,
        technique_id=request.technique_id,
        verdict=verdict,
        detail={"verdict": verdict.verdict.value},
    )


__all__ = ["EmulationOutcome", "run_emulation_validation"]
