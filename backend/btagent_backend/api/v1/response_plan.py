"""Response-plan API (EPIC-3 UC-3.2) — containment & response playbook slice.

Exposes the :class:`ResponsePlanNode` over HTTP: given a confirmed-TP triage
verdict (typed intent + severity + extracted entities), return a **dual-path**
:class:`ResponsePlan` — a strategic NL goal plus a tactical list of concrete
connector-catalog actions.

Safety-by-design (enforced in the engine node, surfaced here):

* Tactical actions are **deterministic**, drawn from a vetted per-intent
  catalog — the LLM (when registered) only refines the strategic narrative,
  never the executable steps.
* **Nothing executes.** Destructive steps are flagged ``destructive`` +
  ``requires_approval`` with a ``rollback`` plan. This endpoint produces a
  *proposal only*; approval + execution (``containment:approve`` /
  ``containment:execute``) are the run-layer's job.

So generating a plan is a plain analyst capability (``response:plan``), parallel
to ``containment:propose`` — proposing is not approving.
"""

from __future__ import annotations

import logging

from btagent_engine import NodeContext
from btagent_engine.reasoning import ResponsePlanInput, ResponsePlanNode, ResponsePlanOutput
from btagent_shared.types.enums import Severity
from btagent_shared.types.triage import TypedIntent
from btagent_shared.utils.ids import generate_id
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from btagent_backend.api.deps import CurrentUser, get_current_user

logger = logging.getLogger("btagent.api.response_plan")

router = APIRouter(prefix="/response-plan", tags=["response-plan"])


class ResponsePlanRequest(BaseModel):
    typed_intent: TypedIntent = Field(
        ..., description="Confirmed Typed Intent from triage (e.g. 'malware_detected')."
    )
    severity: Severity = Field(
        default=Severity.HIGH, description="Confirmed severity; drives the containment window."
    )
    entities: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Affected entities keyed by kind: host / ip / user / domain.",
    )


@router.post("", response_model=ResponsePlanOutput)
async def generate_response_plan(
    body: ResponsePlanRequest,
    user: CurrentUser = Depends(get_current_user),
) -> ResponsePlanOutput:
    """Generate a dual-path containment & response plan (UC-3.2). Proposal only."""
    user.require_permission("response:plan")

    ctx = NodeContext(run_id=generate_id("run"), org_id=user.org_id)
    out = await ResponsePlanNode().run(
        ResponsePlanInput(
            typed_intent=body.typed_intent,
            severity=body.severity,
            entities=body.entities,
        ),
        ctx,
    )
    n_destructive = sum(1 for a in out.plan.tactical_steps if a.destructive)
    logger.info(
        "ResponsePlan: intent=%s severity=%s steps=%d destructive=%d mock=%s (org=%s)",
        body.typed_intent.value,
        body.severity.value,
        len(out.plan.tactical_steps),
        n_destructive,
        out.mock_mode,
        user.org_id,
    )
    return out
