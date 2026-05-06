"""``run_via_engine`` -- the agents-side bridge to the engine runtime.

Sprint 5-foundation. This is the *opt-in* engine path: callers can
choose to run an investigation phase via the engine (load_template +
WorkflowExecutor) instead of the legacy LangGraph subgraph. The legacy
path remains the production default; Sprint 6 will flip the default
once UAT confirms parity.

What this helper wires:

* Loads the named template via :func:`load_template` (Sprint 3C).
* Builds the full Middleware chain in the documented order:
    1. ``ScopeEnforcementMiddleware``  -- outermost; rejects out-of-scope
       data before it reaches any other concern.
    2. ``ClassificationMiddleware``    -- TLP egress gate on input/output.
    3. ``HITLMiddleware``              -- pause on integration nodes that
       require approval.
    4. ``LLMRouterMiddleware``         -- TLP-vs-provider routing for
       reasoning nodes.
    5. ``PromptBudgetMiddleware``      -- cost cap.
    6. ``EvidenceChainMiddleware``     -- audit trail.
    7. ``EventEmitterMiddleware``      -- innermost; events go to the
       WS broadcast channel and are subject to TLP egress + redaction.
* Calls :class:`WorkflowExecutor` with that chain and the seeded
  :class:`NodeContext`.
* Returns the :class:`WorkflowRunResult` (or raises
  :class:`WorkflowPaused` / :class:`WorkflowExecutionError` /
  :class:`TLPViolation`).

What this helper does NOT do:

* Replace ``orchestrator/graph.py`` or ``orchestrator/nodes.py`` --
  those are still the legacy LangGraph wiring. Sprint 6's job to
  rewire ``task_manager.py`` to call this helper instead.
* Render Jinja-style templates. The Sprint 3C templates contain
  ``{{ alert_text }}`` style placeholders that the engine compiler
  doesn't evaluate. Pre-render them in the caller, or wait for the
  expression engine to grow input-templating (separate sprint).
* Resolve missing engine Nodes for legacy-subgraph behaviour. Sprint 4
  shipped most; the remaining ``TODO(sprint3D)`` markers in the
  templates fall through to placeholder LLM calls in mock mode.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from btagent_engine import (
    NodeCategory,
    NodeContext,
    WorkflowExecutor,
    WorkflowRunResult,
)
from btagent_engine.middleware import (
    ClassificationMiddleware,
    EventEmitterMiddleware,
    EvidenceChainMiddleware,
    HITLMiddleware,
    InvestigationScope,
    Middleware,
    PromptBudgetMiddleware,
    ScopeEnforcementMiddleware,
)
from btagent_shared.types.config import TLP, AutonomyLevel, IntegrationAutonomy, ModelTier

from btagent_agents.llm.router import TLPAwareLLMRouter
from btagent_agents.middleware.llm_router import LLMRouterMiddleware
from btagent_agents.orchestrator.templates import load_template

logger = logging.getLogger("btagent.orchestrator.engine_runner")


# Type alias for the WS emit function the orchestrator owns at runtime.
EmitCallable = Callable[..., Awaitable[None]]


def _resolve_provider_handle(
    router: TLPAwareLLMRouter, tlp: TLP
) -> Callable[[str], str]:
    """Adapter that turns ``TLPAwareLLMRouter.resolve(tlp, tier)`` into the
    simpler ``model_handle -> provider`` callable that
    ``LLMRouterMiddleware`` expects.

    The middleware's contract is: given an abstract model handle (e.g.
    ``"claude-haiku"``), pick a concrete provider for the current TLP.
    The router does that resolution but returns ``(provider, model_id)``
    -- we only need the provider here. ``tier`` is inferred from the
    handle's prefix as a best effort (haiku=FAST, sonnet=STANDARD,
    opus=PREMIUM, anything else=STANDARD).
    """

    def _handle_to_tier(handle: str) -> ModelTier:
        h = handle.lower()
        if "haiku" in h or "mini" in h or "flash" in h:
            return ModelTier.FAST
        if "opus" in h or "ultra" in h or "o3" in h:
            return ModelTier.PREMIUM
        return ModelTier.STANDARD

    def _resolve(handle: str) -> str:
        provider, _model_id = router.resolve(tlp, _handle_to_tier(handle))
        return provider

    return _resolve


def build_middleware_chain(
    *,
    tlp: TLP,
    autonomy: AutonomyLevel,
    integration_autonomy: IntegrationAutonomy,
    scope: InvestigationScope | None,
    budget_max_cost_usd: float | None,
    emit_callable: EmitCallable | None,
    llm_router: TLPAwareLLMRouter,
    evidence_records: list[Any],
) -> list[Middleware]:
    """Assemble the middleware stack for one engine-driven workflow run.

    The order is fixed and matches the Sprint 5 helper docstring -- callers
    that want to skip a layer pass ``None`` for the relevant arg.
    ``evidence_records`` is the list ``EvidenceChainMiddleware`` appends
    to; the caller owns it so the audit trail outlives the workflow run.
    """
    chain: list[Middleware] = []

    if scope is not None:
        chain.append(ScopeEnforcementMiddleware(scope=scope))

    chain.append(ClassificationMiddleware(tlp_level=tlp))

    chain.append(
        HITLMiddleware(
            agent_autonomy=autonomy,
            integration_autonomy=integration_autonomy,
        )
    )

    chain.append(
        LLMRouterMiddleware(model_to_provider=_resolve_provider_handle(llm_router, tlp))
    )

    if budget_max_cost_usd is not None:
        chain.append(PromptBudgetMiddleware(max_cost_usd=budget_max_cost_usd))

    chain.append(EvidenceChainMiddleware(records=evidence_records))

    if emit_callable is not None:
        chain.append(
            EventEmitterMiddleware(
                emit_callable=emit_callable,
                tlp_level=tlp,
            )
        )

    return chain


async def run_via_engine(
    template_name: str,
    *,
    investigation_id: str,
    user_id: str | None,
    org_id: str,
    tlp: TLP = TLP.GREEN,
    autonomy: AutonomyLevel = AutonomyLevel.L2_SUPERVISED,
    integration_autonomy: IntegrationAutonomy | None = None,
    scope: InvestigationScope | None = None,
    budget_max_cost_usd: float | None = None,
    emit_callable: EmitCallable | None = None,
    llm_router: TLPAwareLLMRouter | None = None,
    initial_input: dict[str, Any] | None = None,
    run_id: str,
    evidence_records: list[Any] | None = None,
) -> WorkflowRunResult:
    """Execute the named workflow template through the engine.

    Parameters mirror what the legacy orchestrator pulls off the
    investigation row + ``InvestigationConfig``; callers in Sprint 6
    will pass these straight through from ``task_manager.py``.

    Returns the :class:`WorkflowRunResult` on success; raises
    :class:`btagent_engine.runtime.WorkflowPaused` if the HITL gate
    pauses the workflow,
    :class:`btagent_engine.runtime.WorkflowExecutionError` on a
    structural / step failure, and ``TLPViolation`` if egress is
    refused.
    """
    workflow = load_template(template_name)
    router = llm_router or TLPAwareLLMRouter()
    integ = integration_autonomy or IntegrationAutonomy()
    records = evidence_records if evidence_records is not None else []

    middlewares = build_middleware_chain(
        tlp=tlp,
        autonomy=autonomy,
        integration_autonomy=integ,
        scope=scope,
        budget_max_cost_usd=budget_max_cost_usd,
        emit_callable=emit_callable,
        llm_router=router,
        evidence_records=records,
    )

    ctx = NodeContext(
        run_id=run_id,
        investigation_id=investigation_id,
        org_id=org_id,
        user_id=user_id,
        tlp_level=tlp.value,
    )

    logger.info(
        "engine_runner: starting template=%s run=%s investigation=%s tlp=%s middleware=%d",
        template_name,
        run_id,
        investigation_id,
        tlp.value,
        len(middlewares),
    )

    executor = WorkflowExecutor(middlewares=middlewares)
    return await executor.execute(workflow, initial_input=initial_input, ctx=ctx)


__all__ = [
    "EmitCallable",
    "build_middleware_chain",
    "run_via_engine",
]


# Suppress unused-import warning: NodeCategory is exposed here as a
# convenience for callers that want to introspect template Nodes.
_ = NodeCategory
