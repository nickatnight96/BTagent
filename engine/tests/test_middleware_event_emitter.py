"""Tests for the EventEmitter middleware -- lifecycle events + redaction + TLP gate."""

from __future__ import annotations

from typing import Any

import pytest
from btagent_shared.types.config import TLP
from pydantic import BaseModel

from btagent_engine import Node, NodeCategory, NodeContext, NodeMeta, Runner
from btagent_engine.middleware.event_emitter import EventEmitterMiddleware


class _In(BaseModel):
    q: str


class _Out(BaseModel):
    text: str


class _EchoNode(Node[_In, _Out]):
    meta = NodeMeta(
        id="test.echo",
        name="Echo",
        version="0.1.0",
        category=NodeCategory.DATA,
    )
    input_schema = _In
    output_schema = _Out

    async def run(self, input, ctx):
        return _Out(text=input.q)


class _BoomNode(Node[_In, _Out]):
    meta = NodeMeta(
        id="test.boom",
        name="Boom",
        version="0.1.0",
        category=NodeCategory.DATA,
    )
    input_schema = _In
    output_schema = _Out

    async def run(self, input, ctx):
        raise RuntimeError("explode")


class _RecordingEmitter:
    """Captures emit calls for inspection."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    async def __call__(self, event_type: str, /, **payload: Any) -> None:
        self.events.append((event_type, payload))


def _ctx() -> NodeContext:
    return NodeContext(run_id="r1", org_id="org_test")


# --------------------------------------------------------------------------- #
# Happy path: start + end emitted, payloads round-trip
# --------------------------------------------------------------------------- #


async def test_event_emitter_emits_start_and_end():
    sink = _RecordingEmitter()
    runner = Runner([EventEmitterMiddleware(sink)])
    out = await runner.execute(_EchoNode(), _In(q="hello"), _ctx())
    assert out.text == "hello"
    types = [e[0] for e in sink.events]
    assert types == ["node.start", "node.end"]
    start_payload = sink.events[0][1]
    end_payload = sink.events[1][1]
    assert start_payload["node_id"] == "test.echo"
    assert start_payload["input"] == {"q": "hello"}
    assert end_payload["output"] == {"text": "hello"}
    assert end_payload["duration_ms"] is not None


# --------------------------------------------------------------------------- #
# Negative: errors flow through on_error
# --------------------------------------------------------------------------- #


async def test_event_emitter_emits_error_on_failure():
    sink = _RecordingEmitter()
    runner = Runner([EventEmitterMiddleware(sink)])
    with pytest.raises(RuntimeError, match="explode"):
        await runner.execute(_BoomNode(), _In(q=""), _ctx())
    types = [e[0] for e in sink.events]
    assert types == ["node.start", "node.error"]
    err_payload = sink.events[1][1]
    assert err_payload["error_type"] == "RuntimeError"
    assert "explode" in err_payload["error"]


# --------------------------------------------------------------------------- #
# Edge: secret redaction is applied to outgoing payloads
# --------------------------------------------------------------------------- #


async def test_event_emitter_redacts_secrets_in_output():
    sink = _RecordingEmitter()
    runner = Runner([EventEmitterMiddleware(sink)])
    leaky_input = "Bearer abcdefghijklmnopqrstuvwxyz0123456789"
    await runner.execute(_EchoNode(), _In(q=leaky_input), _ctx())

    end_payload = sink.events[1][1]
    rendered = str(end_payload)
    # The bearer token must not appear verbatim anywhere in the emitted payload.
    assert "abcdefghijklmnopqrstuvwxyz0123456789" not in rendered
    assert "[REDACTED:bearer_token]" in rendered


# --------------------------------------------------------------------------- #
# Edge: TLP:RED context drops events instead of crashing the run
# --------------------------------------------------------------------------- #


async def test_event_emitter_drops_when_tlp_red_blocks_egress():
    sink = _RecordingEmitter()
    mw = EventEmitterMiddleware(sink, tlp_level=TLP.RED)
    runner = Runner([mw])
    out = await runner.execute(_EchoNode(), _In(q="ok"), _ctx())
    # Run still succeeds; events are silently dropped (logged, not raised).
    assert out.text == "ok"
    assert sink.events == []
