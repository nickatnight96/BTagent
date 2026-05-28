"""Tests for the real-time TLP violation alerter (EPIC-7 UC-7.2).

Verifies the bridge from the synchronous shared ``emit_violation`` hook to
the async WebSocket hub: a refused egress is broadcast as a
``tlp.violation_attempt`` EventEnvelope.
"""

from __future__ import annotations

import asyncio

import pytest
from btagent_shared.security.tlp import TLPViolation, assert_tlp_allows_egress
from btagent_shared.security.tlp_policy import (
    TLPViolationEvent,
    clear_violation_sink,
    set_violation_sink,
)
from btagent_shared.types.config import TLP
from btagent_shared.types.events import EventEnvelope, EventType

from btagent_backend.services.tlp_alert_sink import make_tlp_violation_sink


class _FakeHub:
    def __init__(self) -> None:
        self.published: list[EventEnvelope] = []

    async def publish(self, envelope: EventEnvelope) -> int:
        self.published.append(envelope)
        return 1


@pytest.fixture(autouse=True)
def _clear_sink():
    clear_violation_sink()
    yield
    clear_violation_sink()


async def test_sink_publishes_violation_envelope():
    hub = _FakeHub()
    sink = make_tlp_violation_sink(hub)
    sink(
        TLPViolationEvent(
            tlp=TLP.RED,
            egress_kind="stix_export",
            channel="egress:stix_export",
            org_id="org_42",
            reason="investigation classification is TLP:RED",
        )
    )
    # The publish is scheduled as a task; let the loop run it.
    await asyncio.sleep(0)
    assert len(hub.published) == 1
    env = hub.published[0]
    assert env.type == EventType.TLP_VIOLATION_ATTEMPT
    assert env.data["tlp"] == "red"
    assert env.data["egress_kind"] == "stix_export"
    assert env.data["org_id"] == "org_42"


async def test_egress_gate_block_broadcasts_alert():
    """End-to-end: a refused egress fires the registered sink -> hub publish."""
    hub = _FakeHub()
    set_violation_sink(make_tlp_violation_sink(hub))

    with pytest.raises(TLPViolation):
        assert_tlp_allows_egress({"k": "v"}, "mcp_return", TLP.RED, org_id="org_7")

    await asyncio.sleep(0)
    assert len(hub.published) == 1
    assert hub.published[0].data["egress_kind"] == "mcp_return"
    assert hub.published[0].data["org_id"] == "org_7"


async def test_sink_swallows_when_no_event_loop():
    # Called from a worker thread (no running loop) -> must not raise, must
    # not publish. Run the sync sink inside a thread to remove the loop.
    hub = _FakeHub()
    sink = make_tlp_violation_sink(hub)
    event = TLPViolationEvent(tlp=TLP.RED, egress_kind="event_emit", channel="x")

    error: list[BaseException] = []

    def _run() -> None:
        try:
            sink(event)
        except BaseException as e:  # noqa: BLE001 - capture for assertion
            error.append(e)

    await asyncio.to_thread(_run)
    assert error == []  # no exception propagated
    assert hub.published == []  # nothing published without a loop
