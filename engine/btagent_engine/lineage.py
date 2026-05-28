"""Lineage-graph projection over the EvidenceChain (EPIC-7 UC-7.1).

UC-7.1 requires a *lineage graph* — analyst query → LLM prompt → tool call
→ response → raw log — built over the tamper-evident audit chain that
:class:`btagent_engine.middleware.evidence_chain.EvidenceChainMiddleware`
already produces. That middleware appends one
:class:`EvidenceRecord` per successful node run to a single list, hash-
linking each record to its predecessor (``prev_hash`` == the previous
record's ``link_hash``), so the records form one global linear chain.

This module is a **pure projection**: it turns a sequence of
``EvidenceRecord`` into a graph of :class:`LineageNode` / :class:`LineageEdge`,
verifies the hash chain is intact, and supports point-in-time replay
(the prefix of the chain up to a chosen record). No I/O, no DB — the
forensics surface (API + UI) consumes this; it is not new substrate.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.middleware.evidence_chain import (
    GENESIS_HASH,
    EvidenceRecord,
    _link_hash,  # single source of truth for the chain-hash formula
)


class LineageNode(BaseModel):
    """A graph node — one Node execution recorded in the chain."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(..., description="The record's link_hash; unique per execution.")
    run_id: str
    node_id: str
    input_hash: str
    output_hash: str
    timestamp: str = Field(..., description="ISO-8601 execution time.")
    sequence: int = Field(..., description="0-based position in the global chain.")


class LineageEdge(BaseModel):
    """A directed edge from a predecessor execution to its successor."""

    model_config = ConfigDict(frozen=True)

    source: str = Field(..., description="link_hash of the predecessor.")
    target: str = Field(..., description="link_hash of the successor.")
    kind: str = "chain"


class LineageGraph(BaseModel):
    """The projected lineage DAG plus chain-integrity verdict."""

    model_config = ConfigDict(frozen=True)

    nodes: tuple[LineageNode, ...] = ()
    edges: tuple[LineageEdge, ...] = ()
    intact: bool = True
    broken_at: str | None = Field(
        default=None,
        description="link_hash (or node_id) of the first record that breaks the chain.",
    )


def verify_chain(records: Sequence[EvidenceRecord]) -> tuple[bool, str | None]:
    """Verify the global hash chain.

    Returns ``(intact, broken_at)`` where ``broken_at`` is the ``link_hash``
    of the first record whose ``prev_hash`` linkage or recomputed
    ``link_hash`` does not hold (or ``None`` if intact).
    """
    expected_prev = GENESIS_HASH
    for rec in records:
        if rec.prev_hash != expected_prev:
            return False, rec.link_hash
        recomputed = _link_hash(
            rec.node_id,
            rec.input_hash,
            rec.output_hash,
            rec.run_id,
            rec.timestamp.isoformat(),
            rec.prev_hash,
        )
        if recomputed != rec.link_hash:
            return False, rec.link_hash
        expected_prev = rec.link_hash
    return True, None


def build_lineage_graph(
    records: Sequence[EvidenceRecord],
    *,
    verify: bool = True,
) -> LineageGraph:
    """Project a global EvidenceChain into a verifiable lineage DAG.

    Edges connect each record to its immediate predecessor in append order
    (the genesis record has no incoming edge). When *verify* is true the
    hash chain is checked end-to-end; a break sets ``intact=False`` and
    ``broken_at`` to the offending record but still returns the full graph
    so a forensics view can highlight exactly where tampering occurred.
    """
    nodes: list[LineageNode] = []
    edges: list[LineageEdge] = []

    for seq, rec in enumerate(records):
        nodes.append(
            LineageNode(
                id=rec.link_hash,
                run_id=rec.run_id,
                node_id=rec.node_id,
                input_hash=rec.input_hash,
                output_hash=rec.output_hash,
                timestamp=rec.timestamp.isoformat(),
                sequence=seq,
            )
        )
        if rec.prev_hash != GENESIS_HASH:
            edges.append(LineageEdge(source=rec.prev_hash, target=rec.link_hash))

    intact, broken_at = verify_chain(records) if verify else (True, None)
    return LineageGraph(
        nodes=tuple(nodes),
        edges=tuple(edges),
        intact=intact,
        broken_at=broken_at,
    )


def replay_to(
    records: Sequence[EvidenceRecord],
    link_hash: str,
) -> list[EvidenceRecord]:
    """Return the chain prefix up to and including the record with *link_hash*.

    Supports UC-7.1 point-in-time replay: reconstruct workflow state as of
    any recorded step. Raises :class:`KeyError` if no record matches.
    """
    prefix: list[EvidenceRecord] = []
    for rec in records:
        prefix.append(rec)
        if rec.link_hash == link_hash:
            return prefix
    raise KeyError(f"No evidence record with link_hash={link_hash!r}")


__all__ = [
    "LineageEdge",
    "LineageGraph",
    "LineageNode",
    "build_lineage_graph",
    "replay_to",
    "verify_chain",
]
