"""Tests for the Classification (TLP egress) middleware."""

from __future__ import annotations

import pytest
from btagent_shared.security import TLPViolation
from btagent_shared.types.config import TLP
from pydantic import BaseModel

from btagent_engine import Node, NodeCategory, NodeContext, NodeMeta, Runner
from btagent_engine.middleware.classification import ClassificationMiddleware


class _In(BaseModel):
    q: str
    tlp_level: str | None = None


class _Out(BaseModel):
    text: str
    tlp_level: str | None = None


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
        return _Out(text=input.q, tlp_level=input.tlp_level)


def _ctx(tlp: str = "green") -> NodeContext:
    return NodeContext(run_id="r", org_id="org_test", tlp_level=tlp)


# --------------------------------------------------------------------------- #
# Happy: green/amber data flows through both gates
# --------------------------------------------------------------------------- #


async def test_classification_passes_amber_data_through():
    runner = Runner([ClassificationMiddleware(tlp_level=TLP.AMBER)])
    out = await runner.execute(_EchoNode(), _In(q="hi"), _ctx())
    assert out.text == "hi"


# --------------------------------------------------------------------------- #
# Negative: TLP:RED context blocks at before_run
# --------------------------------------------------------------------------- #


async def test_classification_blocks_red_context_on_input():
    runner = Runner([ClassificationMiddleware(tlp_level=TLP.RED)])
    with pytest.raises(TLPViolation):
        await runner.execute(_EchoNode(), _In(q="hi"), _ctx())


# --------------------------------------------------------------------------- #
# Edge: payload-tagged TLP:RED is caught even when the context is GREEN
# --------------------------------------------------------------------------- #


async def test_classification_blocks_red_tagged_payload():
    """An input field carrying ``tlp_level='red'`` triggers the gate."""
    runner = Runner([ClassificationMiddleware(tlp_level=TLP.GREEN)])
    with pytest.raises(TLPViolation):
        await runner.execute(_EchoNode(), _In(q="x", tlp_level="red"), _ctx())


# --------------------------------------------------------------------------- #
# Edge: when no explicit tlp_level is set, the middleware uses ctx.tlp_level
# --------------------------------------------------------------------------- #


async def test_classification_falls_back_to_context_tlp():
    runner = Runner([ClassificationMiddleware()])  # no tlp_level override
    with pytest.raises(TLPViolation):
        await runner.execute(_EchoNode(), _In(q="hi"), _ctx(tlp="red"))
