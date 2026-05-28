"""Tests for the UC-7.1 lineage-graph projection over the EvidenceChain.

Builds real (correctly-hashed) chains via the same hash formula the
middleware uses, then verifies projection, integrity detection, and
point-in-time replay. In ``agents/tests`` so CI runs it (engine/tests is
not wired into CI).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from btagent_engine.lineage import (
    LineageGraph,
    build_lineage_graph,
    replay_to,
    verify_chain,
)
from btagent_engine.middleware.evidence_chain import (
    GENESIS_HASH,
    EvidenceRecord,
    _link_hash,
    _sha256_of,
)


def _chain(specs: list[tuple[str, str]]) -> list[EvidenceRecord]:
    """Build a valid global chain from (node_id, run_id) pairs.

    Mirrors EvidenceChainMiddleware: prev_hash is the previous record's
    link_hash regardless of run_id (the chain is global, not per-run).
    """
    recs: list[EvidenceRecord] = []
    prev = GENESIS_HASH
    for i, (node_id, run_id) in enumerate(specs):
        in_h = _sha256_of({"node": node_id, "i": i, "side": "in"})
        out_h = _sha256_of({"node": node_id, "i": i, "side": "out"})
        ts = datetime(2026, 5, 28, 12, i, tzinfo=UTC)
        link = _link_hash(node_id, in_h, out_h, run_id, ts.isoformat(), prev)
        recs.append(
            EvidenceRecord(
                run_id=run_id,
                node_id=node_id,
                prev_hash=prev,
                link_hash=link,
                input_hash=in_h,
                output_hash=out_h,
                timestamp=ts,
            )
        )
        prev = link
    return recs


_LINEAGE = [
    ("nl_query", "r1"),
    ("llm_call", "r1"),
    ("splunk_search", "r1"),
    ("score_ioc", "r1"),
]


# --------------------------------------------------------------------------- #
# Projection
# --------------------------------------------------------------------------- #


def test_build_graph_node_and_edge_counts():
    g = build_lineage_graph(_chain(_LINEAGE))
    assert isinstance(g, LineageGraph)
    assert len(g.nodes) == 4
    # Genesis record has no incoming edge -> n-1 edges in a linear chain.
    assert len(g.edges) == 3


def test_nodes_carry_node_id_and_sequence_in_order():
    g = build_lineage_graph(_chain(_LINEAGE))
    assert [n.node_id for n in g.nodes] == ["nl_query", "llm_call", "splunk_search", "score_ioc"]
    assert [n.sequence for n in g.nodes] == [0, 1, 2, 3]
    assert all(n.id == n.id for n in g.nodes)  # id == link_hash, populated


def test_edges_link_predecessor_to_successor():
    recs = _chain(_LINEAGE)
    g = build_lineage_graph(recs)
    # Each edge connects record[i-1].link_hash -> record[i].link_hash.
    for i, edge in enumerate(g.edges, start=1):
        assert edge.source == recs[i - 1].link_hash
        assert edge.target == recs[i].link_hash
        assert edge.kind == "chain"


def test_empty_records_yield_empty_intact_graph():
    g = build_lineage_graph([])
    assert g.nodes == ()
    assert g.edges == ()
    assert g.intact is True
    assert g.broken_at is None


def test_first_node_has_no_incoming_edge():
    recs = _chain(_LINEAGE)
    g = build_lineage_graph(recs)
    targets = {e.target for e in g.edges}
    assert recs[0].link_hash not in targets


# --------------------------------------------------------------------------- #
# Integrity verification
# --------------------------------------------------------------------------- #


def test_valid_chain_is_intact():
    intact, broken_at = verify_chain(_chain(_LINEAGE))
    assert intact is True
    assert broken_at is None


def test_tampered_content_detected():
    recs = _chain(_LINEAGE)
    # Tamper record[1]'s input without recomputing its link_hash.
    recs[1] = recs[1].model_copy(update={"input_hash": "0" * 64})
    intact, broken_at = verify_chain(recs)
    assert intact is False
    assert broken_at == recs[1].link_hash


def test_broken_prev_linkage_detected():
    recs = _chain(_LINEAGE)
    # Sever the linkage at record[2] by pointing prev_hash elsewhere.
    recs[2] = recs[2].model_copy(update={"prev_hash": "f" * 64})
    intact, broken_at = verify_chain(recs)
    assert intact is False
    assert broken_at == recs[2].link_hash


def test_tampered_node_id_detected():
    # node_id is displayed in the lineage view, so re-labelling a step must
    # invalidate the chain (HIGH-4: node_id is bound by the hash).
    recs = _chain(_LINEAGE)
    recs[1] = recs[1].model_copy(update={"node_id": "evil_node"})
    intact, broken_at = verify_chain(recs)
    assert intact is False
    assert broken_at == recs[1].link_hash


def test_tampered_timestamp_detected():
    # timestamp is displayed too; back-dating a record must be detected.
    recs = _chain(_LINEAGE)
    recs[2] = recs[2].model_copy(update={"timestamp": datetime(2099, 1, 1, tzinfo=UTC)})
    intact, broken_at = verify_chain(recs)
    assert intact is False
    assert broken_at == recs[2].link_hash


def test_build_graph_reports_break_but_returns_full_graph():
    recs = _chain(_LINEAGE)
    recs[2] = recs[2].model_copy(update={"input_hash": "0" * 64})
    g = build_lineage_graph(recs)
    assert g.intact is False
    assert g.broken_at == recs[2].link_hash
    # Full graph still returned so a forensics view can highlight the break.
    assert len(g.nodes) == 4


def test_verify_false_skips_integrity_check():
    recs = _chain(_LINEAGE)
    recs[1] = recs[1].model_copy(update={"input_hash": "0" * 64})
    g = build_lineage_graph(recs, verify=False)
    assert g.intact is True
    assert g.broken_at is None


def test_global_chain_spans_multiple_runs():
    # The middleware chains globally across runs; verification must hold.
    recs = _chain([("nl_query", "r1"), ("llm_call", "r2"), ("export", "r3")])
    intact, broken_at = verify_chain(recs)
    assert intact is True
    g = build_lineage_graph(recs)
    assert {n.run_id for n in g.nodes} == {"r1", "r2", "r3"}
    assert len(g.edges) == 2


# --------------------------------------------------------------------------- #
# Point-in-time replay
# --------------------------------------------------------------------------- #


def test_replay_to_returns_inclusive_prefix():
    recs = _chain(_LINEAGE)
    prefix = replay_to(recs, recs[2].link_hash)
    assert [r.node_id for r in prefix] == ["nl_query", "llm_call", "splunk_search"]


def test_replay_to_first_record():
    recs = _chain(_LINEAGE)
    assert replay_to(recs, recs[0].link_hash) == [recs[0]]


def test_replay_to_unknown_hash_raises():
    recs = _chain(_LINEAGE)
    with pytest.raises(KeyError):
        replay_to(recs, "nonexistent")
