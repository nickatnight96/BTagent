"""Tests for Middleware composition + Runner.execute."""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from btagent_engine import (
    Middleware,
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    Runner,
)


class _Input(BaseModel):
    n: int


class _Output(BaseModel):
    doubled: int


class _DoubleNode(Node[_Input, _Output]):
    meta = NodeMeta(
        id="test.double",
        name="Double",
        version="0.1.0",
        category=NodeCategory.DATA,
    )
    input_schema = _Input
    output_schema = _Output

    async def run(self, input, ctx):
        return _Output(doubled=input.n * 2)


class _BoomNode(Node[_Input, _Output]):
    meta = NodeMeta(
        id="test.boom",
        name="Boom",
        version="0.1.0",
        category=NodeCategory.DATA,
    )
    input_schema = _Input
    output_schema = _Output

    async def run(self, input, ctx):
        raise RuntimeError("boom")


class _RecordingMW(Middleware):
    def __init__(self, name: str, log: list[str]) -> None:
        self.name = name
        self._log = log

    async def before_run(self, node, input, ctx):
        self._log.append(f"{self.name}.before")

    async def after_run(self, node, input, output, ctx):
        self._log.append(f"{self.name}.after")

    async def on_error(self, node, input, error, ctx):
        self._log.append(f"{self.name}.on_error:{type(error).__name__}")


def _ctx() -> NodeContext:
    return NodeContext(run_id="r", org_id="org_test")


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


async def test_runner_executes_node_with_no_middleware():
    runner = Runner()
    out = await runner.execute(_DoubleNode(), _Input(n=3), _ctx())
    assert isinstance(out, _Output)
    assert out.doubled == 6


async def test_runner_validates_dict_payload_against_schema():
    runner = Runner()
    out = await runner.execute(_DoubleNode(), {"n": 4}, _ctx())
    assert out.doubled == 8


async def test_runner_validates_output_defensively():
    """If a node returns a dict matching the output_schema, the Runner
    should still surface a typed model."""

    class _LooseNode(Node[_Input, _Output]):
        meta = NodeMeta(
            id="test.loose",
            name="Loose",
            version="0.1.0",
            category=NodeCategory.DATA,
        )
        input_schema = _Input
        output_schema = _Output

        async def run(self, input, ctx):
            return {"doubled": input.n * 2}  # type: ignore[return-value]

    out = await Runner().execute(_LooseNode(), _Input(n=5), _ctx())
    assert isinstance(out, _Output)
    assert out.doubled == 10


# --------------------------------------------------------------------------- #
# Middleware ordering
# --------------------------------------------------------------------------- #


async def test_before_runs_in_order_after_in_reverse():
    """Documented contract: before_run is registration-order, after_run
    is reverse. Mirrors ASGI / express request-response symmetry."""
    log: list[str] = []
    runner = Runner([_RecordingMW("outer", log), _RecordingMW("inner", log)])
    await runner.execute(_DoubleNode(), _Input(n=1), _ctx())
    assert log == [
        "outer.before",
        "inner.before",
        "inner.after",
        "outer.after",
    ]


async def test_on_error_runs_in_reverse_and_reraises():
    log: list[str] = []
    runner = Runner([_RecordingMW("outer", log), _RecordingMW("inner", log)])
    with pytest.raises(RuntimeError, match="boom"):
        await runner.execute(_BoomNode(), _Input(n=1), _ctx())
    assert log == [
        "outer.before",
        "inner.before",
        "inner.on_error:RuntimeError",
        "outer.on_error:RuntimeError",
    ]


async def test_middleware_cannot_swallow_errors():
    """on_error has no return value; the Runner re-raises regardless."""

    class _SwallowingMW(Middleware):
        name = "swallow"

        async def on_error(self, node, input, error, ctx):
            return None  # nothing we can do here changes the outcome

    with pytest.raises(RuntimeError, match="boom"):
        await Runner([_SwallowingMW()]).execute(_BoomNode(), _Input(n=1), _ctx())


async def test_after_run_not_called_on_error():
    """If run() raises, after_run is skipped on every middleware."""
    log: list[str] = []
    runner = Runner([_RecordingMW("only", log)])
    with pytest.raises(RuntimeError):
        await runner.execute(_BoomNode(), _Input(n=1), _ctx())
    assert "only.after" not in log
    assert "only.on_error:RuntimeError" in log
