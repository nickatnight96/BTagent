"""Manual trigger Node -- the entry point for analyst-initiated workflow runs.

A *trigger* Node is the starting point of a workflow: the runner uses
the trigger's output as the seed payload for whatever downstream nodes
the workflow file wires up. ``ManualTriggerNode`` is the simplest
member of the family -- it does no work and just echoes whatever JSON
the analyst pasted into the launch dialog.

Why a no-op Node still earns its place in the registry:

1. Workflows are graphs and every graph needs an entry point. Modelling
   the manual trigger as a Node (rather than a special-cased "start"
   marker) means the canvas UI, the compiler, and the runner all use
   the same vocabulary -- there are no two ways to start a workflow.

2. Future trigger variants (webhook, schedule, alert ingest -- all
   landing in Phase 3 per the redesign plan) will share this base
   shape: a ``payload: dict`` output that downstream nodes consume.
   Keeping the manual variant trivial makes the contract obvious.

3. Defensive validation. Because the input is a free-form ``dict``,
   the only validation is "is it a dict at all"; pydantic handles that.
   Downstream nodes get to enforce their own schemas on whatever the
   trigger emits.

Mock mode is deliberately *not* a concept here -- there's no external
service to stub; behaviour is identical in test, dev, and prod.
"""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)


class ManualTriggerInput(BaseModel):
    """Input to the manual trigger -- arbitrary JSON the analyst supplies."""

    model_config = ConfigDict(extra="forbid")

    payload: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form JSON payload pasted into the launch dialog. "
        "Downstream nodes are responsible for their own schema validation; "
        "the trigger imposes none beyond 'is a dict'.",
    )


class ManualTriggerOutput(BaseModel):
    """Output of the manual trigger -- echoes the input payload verbatim."""

    model_config = ConfigDict(extra="forbid")

    payload: dict[str, Any] = Field(
        default_factory=dict,
        description="The payload, returned unchanged. Triggers do no work; "
        "they exist to seed the workflow run with structured data.",
    )


@NodeRegistry.register
class ManualTriggerNode(Node[ManualTriggerInput, ManualTriggerOutput]):
    """Manually-fired workflow entry point.

    The analyst clicks "Run" in the canvas, optionally pastes a JSON
    payload, and the runner uses this Node's output as the seed for the
    rest of the workflow. No external I/O, no mock-mode flag, no work
    beyond payload echo.

    Webhook / schedule / alert variants ship in Phase 3.
    """

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="trigger.manual",
        name="Trigger: Manual",
        version="0.1.0",
        category=NodeCategory.TRIGGER,
        description="Analyst-initiated workflow entry point. Echoes the launch "
        "payload as-is for downstream nodes to consume. Webhook / schedule / "
        "alert trigger variants land in Phase 3.",
    )
    input_schema: ClassVar[type[BaseModel]] = ManualTriggerInput
    output_schema: ClassVar[type[BaseModel]] = ManualTriggerOutput

    async def run(
        self,
        input: ManualTriggerInput,
        ctx: NodeContext,
    ) -> ManualTriggerOutput:
        # Trigger Nodes intentionally do no work -- they exist purely to
        # seed the workflow run with whatever payload the caller supplied.
        # Returning a fresh instance (rather than mutating *input*) keeps
        # the input/output models distinct in case a future variant adds
        # output-only fields like trigger timestamps.
        return ManualTriggerOutput(payload=dict(input.payload))


__all__ = [
    "ManualTriggerInput",
    "ManualTriggerNode",
    "ManualTriggerOutput",
]
