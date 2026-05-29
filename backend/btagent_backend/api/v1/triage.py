"""Alert-triage API (EPIC-3 UC-3.1) — engine-backed triage slice.

Exposes the AlertTriageNode over HTTP: submit a raw alert, get back a
reviewed case (Typed Intent + proposed severity/disposition + confidence
+ explanation + evidence trail + 2–3 read-only next steps). The node is
advisory and never executes an action, so the endpoint is a plain
read/classify call — the analyst approves any follow-up.

Mock-mode in dev (BTAGENT_MOCK_LLM defaults true → deterministic keyword
classifier); the real-LLM path activates when a client is registered.
The node is client-or-deterministic and never raises, so there is no 501
path here.
"""

from __future__ import annotations

import logging

from btagent_engine import NodeContext
from btagent_engine.reasoning import AlertTriageInput, AlertTriageNode
from btagent_shared.types.enums import Severity
from btagent_shared.types.triage import Alert, TriageResult
from btagent_shared.utils.ids import generate_id
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from btagent_backend.api.deps import CurrentUser, get_current_user

logger = logging.getLogger("btagent.api.triage")

router = APIRouter(prefix="/triage", tags=["triage"])


class TriageRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=2000, description="Alert title / rule name.")
    description: str = Field(default="", max_length=20000)
    source: str = Field(default="", max_length=200, description="Originating tool, e.g. 'splunk'.")
    severity: Severity = Field(
        default=Severity.MEDIUM, description="Severity as reported by the source detector."
    )
    entities: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Extracted entities keyed by kind: ip / user / host / process / hash.",
    )


@router.post("", response_model=TriageResult)
async def triage_alert(
    body: TriageRequest,
    user: CurrentUser = Depends(get_current_user),
) -> TriageResult:
    """Auto-triage a raw alert into a reviewed case (UC-3.1). Read-only."""
    user.require_permission("triage:run")

    alert = Alert(
        id=generate_id("alrt"),
        source=body.source,
        title=body.title,
        description=body.description,
        severity=body.severity,
        entities=body.entities,
    )
    ctx = NodeContext(run_id=generate_id("run"), org_id=user.org_id)
    out = await AlertTriageNode().run(AlertTriageInput(alert=alert), ctx)
    logger.info(
        "Triage: intent=%s disposition=%s severity=%s->%s (org=%s)",
        out.result.typed_intent.value,
        out.result.disposition.value,
        body.severity.value,
        out.result.proposed_severity.value,
        user.org_id,
    )
    return out.result
