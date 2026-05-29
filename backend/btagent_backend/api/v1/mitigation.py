"""Bulk-mitigation API (EPIC-3 UC-3.3) — bulk IOC block & mitigation slice.

Exposes the :class:`BulkMitigationNode` over HTTP: submit a batch of IOCs an
analyst wants to block, get back a per-tool :class:`MitigationPlan` — each IOC
screened against a never-block allowlist, validated, routed to the connector +
policy object that would enforce the block, with a policy-change preview and a
rollback.

Safety-by-design (enforced in the engine node, surfaced here):

* Block/skip decisions are **deterministic** — the LLM (when registered) only
  refines the plan summary, never the per-IOC decisions.
* **Nothing executes.** Block actions are flagged ``destructive`` +
  ``requires_approval`` with a ``rollback``. This is a *proposal only*;
  approval + execution are the run-layer's job (``containment:*``).

Generating a plan is a plain analyst capability (``mitigation:plan``), parallel
to ``containment:propose`` — proposing is not approving.
"""

from __future__ import annotations

import logging

from btagent_engine import NodeContext
from btagent_engine.reasoning import (
    BulkMitigationInput,
    BulkMitigationNode,
    BulkMitigationOutput,
    IOCRef,
)
from btagent_shared.utils.ids import generate_id
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from btagent_backend.api.deps import CurrentUser, get_current_user

logger = logging.getLogger("btagent.api.mitigation")

router = APIRouter(prefix="/mitigation", tags=["mitigation"])

# Hard cap on the batch — a bulk-block proposal over thousands of IOCs is a DoS
# vector on the planner and a foot-gun for the approver. 500 is well above any
# real analyst workflow.
_MAX_IOCS = 500


class MitigationPlanRequest(BaseModel):
    iocs: list[IOCRef] = Field(
        default_factory=list, max_length=_MAX_IOCS, description="IOCs to consider for blocking."
    )
    extra_allowlist: list[str] = Field(
        default_factory=list,
        max_length=_MAX_IOCS,
        description="Caller-supplied exact values to never block.",
    )


@router.post("", response_model=BulkMitigationOutput)
async def plan_bulk_mitigation(
    body: MitigationPlanRequest,
    user: CurrentUser = Depends(get_current_user),
) -> BulkMitigationOutput:
    """Plan a bulk IOC block across connectors (UC-3.3). Proposal only."""
    user.require_permission("mitigation:plan")

    ctx = NodeContext(run_id=generate_id("run"), org_id=user.org_id)
    out = await BulkMitigationNode().run(
        BulkMitigationInput(iocs=body.iocs, extra_allowlist=body.extra_allowlist),
        ctx,
    )
    logger.info(
        "BulkMitigation: in=%d block=%d skip=%d tools=%s mock=%s (org=%s)",
        len(body.iocs),
        out.plan.block_count,
        out.plan.skip_count,
        ",".join(out.plan.tools),
        out.mock_mode,
        user.org_id,
    )
    return out
