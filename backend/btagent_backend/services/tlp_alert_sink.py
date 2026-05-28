"""Real-time TLP violation alerter (EPIC-7 UC-7.2).

Bridges the synchronous ``emit_violation`` hook in
``btagent_shared.security.tlp_policy`` to the async WebSocket hub: every
refused egress (TLP:RED blocked at the MCP-return / EventEmitter / STIX /
knowledge-ingest gates) is broadcast as a ``tlp.violation_attempt`` event
so the analyst surface can alert in real time.

The shared sink contract is sync and must never raise (alerting can't
break egress enforcement). Publishing is async, so the sink schedules the
publish on the running event loop; if there is no loop (e.g. a violation
raised from a worker thread), it logs and drops the alert rather than
failing the egress path.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Protocol

from btagent_shared.security.tlp_policy import TLPViolationEvent
from btagent_shared.types.events import EventEnvelope, EventType

logger = logging.getLogger("btagent.tlp_alert")

# Violations aren't necessarily tied to one investigation; broadcast on a
# stable system pseudo-id (the hub also fans out to the global channel).
_SYSTEM_INVESTIGATION_ID = "system"


class _Publisher(Protocol):
    async def publish(self, envelope: EventEnvelope) -> int: ...


def _to_envelope(event: TLPViolationEvent) -> EventEnvelope:
    return EventEnvelope(
        type=EventType.TLP_VIOLATION_ATTEMPT,
        investigation_id=_SYSTEM_INVESTIGATION_ID,
        data={
            "tlp": event.tlp.value,
            "egress_kind": event.egress_kind,
            "channel": event.channel,
            "org_id": event.org_id,
            "matched_policy_id": event.matched_policy_id,
            "reason": event.reason,
            "occurred_at": event.occurred_at.isoformat(),
        },
    )


def make_tlp_violation_sink(hub: _Publisher):
    """Build a sync sink that forwards violations to *hub* on the event loop."""

    def sink(event: TLPViolationEvent) -> None:
        envelope = _to_envelope(event)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No running loop (sync/threaded caller) — alerting is best
            # effort; record it and move on without breaking the gate.
            logger.warning(
                "TLP violation (no event loop to broadcast): tlp=%s egress=%s org=%s",
                event.tlp.value,
                event.egress_kind,
                event.org_id,
            )
            return
        loop.create_task(hub.publish(envelope))

    return sink


__all__ = ["make_tlp_violation_sink"]
