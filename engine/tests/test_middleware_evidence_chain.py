"""Tests for the EvidenceChain middleware -- hash-linked audit trail."""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from btagent_engine import Node, NodeCategory, NodeContext, NodeMeta, Runner
from btagent_engine.middleware.evidence_chain import (
    GENESIS_HASH,
    EvidenceChainMiddleware,
    EvidenceRecord,
)


class _In(BaseModel):
    n: int


class _Out(BaseModel):
    doubled: int


class _DoubleNode(Node[_In, _Out]):
    meta = NodeMeta(
        id="test.double",
        name="Double",
        version="0.1.0",
        category=NodeCategory.DATA,
    )
    input_schema = _In
    output_schema = _Out

    async def run(self, input, ctx):
        return _Out(doubled=input.n * 2)


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
        raise RuntimeError("nope")


def _ctx(run_id: str = "r1") -> NodeContext:
    return NodeContext(run_id=run_id, org_id="org_test")


# --------------------------------------------------------------------------- #
# Happy: a successful run produces a single record linked to GENESIS
# --------------------------------------------------------------------------- #


async def test_evidence_chain_appends_record_after_run():
    records: list[EvidenceRecord] = []
    runner = Runner([EvidenceChainMiddleware(records)])
    await runner.execute(_DoubleNode(), _In(n=2), _ctx())

    assert len(records) == 1
    rec = records[0]
    assert rec.run_id == "r1"
    assert rec.node_id == "test.double"
    assert rec.prev_hash == GENESIS_HASH
    assert len(rec.link_hash) == 64
    assert rec.input_hash != rec.output_hash


# --------------------------------------------------------------------------- #
# Negative: a failed run leaves the chain untouched
# --------------------------------------------------------------------------- #


async def test_evidence_chain_skips_record_on_error():
    records: list[EvidenceRecord] = []
    runner = Runner([EvidenceChainMiddleware(records)])
    with pytest.raises(RuntimeError):
        await runner.execute(_BoomNode(), _In(n=1), _ctx())
    assert records == []


# --------------------------------------------------------------------------- #
# Edge: each record's prev_hash equals the previous link_hash; tampering
# with any record breaks the chain at that point.
# --------------------------------------------------------------------------- #


async def test_evidence_chain_links_subsequent_records():
    records: list[EvidenceRecord] = []
    runner = Runner([EvidenceChainMiddleware(records)])

    await runner.execute(_DoubleNode(), _In(n=1), _ctx(run_id="r1"))
    await runner.execute(_DoubleNode(), _In(n=2), _ctx(run_id="r2"))
    await runner.execute(_DoubleNode(), _In(n=3), _ctx(run_id="r3"))

    assert len(records) == 3
    assert records[0].prev_hash == GENESIS_HASH
    assert records[1].prev_hash == records[0].link_hash
    assert records[2].prev_hash == records[1].link_hash
    # Each link_hash is unique because the inputs differ.
    assert len({r.link_hash for r in records}) == 3
