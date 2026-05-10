"""Trigger nodes -- the entry points that seed a workflow run.

Every workflow starts with exactly one trigger Node. The trigger emits
a payload that the downstream nodes consume; what shape that payload
takes is the trigger's choice (manual triggers echo whatever JSON the
analyst pasted; webhook triggers will emit the request body; schedule
triggers will emit the cron firing context; etc.).

Sprint 2.5 ships the manual trigger only -- the simplest member of the
family. Webhook / schedule / alert variants land in Phase 3 per the
redesign plan; they all subclass ``Node`` with category
``NodeCategory.TRIGGER`` and follow the same input-shape-defines-payload
contract.
"""

from btagent_engine.triggers.manual import (
    ManualTriggerInput,
    ManualTriggerNode,
    ManualTriggerOutput,
)

__all__ = [
    "ManualTriggerInput",
    "ManualTriggerNode",
    "ManualTriggerOutput",
]
