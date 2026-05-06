"""Tests for KnowledgeSearchNode + the FakeKnowledgeClient contract.

The Node delegates to a :class:`KnowledgeClient`; tests stub the client
with :class:`FakeKnowledgeClient` and assert on the contract surface
(top_k truncation, source_type filter, empty-query short-circuit, query
echo, registry registration, end-to-end through the Runner).
"""

from __future__ import annotations

import pytest

from btagent_engine import NodeContext, NodeRegistry, Runner
from btagent_engine.knowledge import (
    FakeKnowledgeClient,
    KnowledgeSearchInput,
    KnowledgeSearchNode,
    KnowledgeSearchOutput,
)


def _ctx() -> NodeContext:
    return NodeContext(
        run_id="r_knowledge_search",
        org_id="org_default",
        investigation_id="inv_test",
    )


def _seed_chunks(n: int, *, source_type: str = "runbook") -> list[dict]:
    """Build *n* deterministic chunk dicts, descending relevance score."""
    return [
        {
            "chunk_content": f"Chunk body #{i}",
            "document_title": f"Doc {i}",
            "source_type": source_type,
            "relevance_score": 1.0 - (i * 0.1),
            "metadata": {"position": i},
        }
        for i in range(n)
    ]


# ---------------------------------------------------------------------------
# Direct Node.run tests (constructor-injected client)
# ---------------------------------------------------------------------------


async def test_search_returns_n_results_when_client_has_n_matching_chunks():
    """Happy path: every seeded chunk should make it back through the Node
    when top_k is large enough to cover them."""
    fake = FakeKnowledgeClient()
    fake.seed(_seed_chunks(3))
    node = KnowledgeSearchNode(client=fake)

    out = await node.run(
        KnowledgeSearchInput(query="lateral movement", top_k=5),
        _ctx(),
    )
    assert isinstance(out, KnowledgeSearchOutput)
    assert len(out.results) == 3
    assert [r.document_title for r in out.results] == ["Doc 0", "Doc 1", "Doc 2"]
    # metadata must round-trip through the adapter.
    assert out.results[0].metadata == {"position": 0}


async def test_search_truncates_to_top_k():
    """top_k caps the result list; the client receives the value verbatim
    so the truncation can happen at the source where it's cheapest."""
    fake = FakeKnowledgeClient()
    fake.seed(_seed_chunks(10))
    node = KnowledgeSearchNode(client=fake)

    out = await node.run(
        KnowledgeSearchInput(query="phishing", top_k=3),
        _ctx(),
    )
    assert len(out.results) == 3
    assert fake.search_calls[-1]["top_k"] == 3


async def test_search_passes_source_type_filter_through_to_client():
    """source_type must reach the client unchanged; the fake also enforces
    the filter so we can assert end-to-end behaviour."""
    fake = FakeKnowledgeClient()
    fake.seed(
        _seed_chunks(2, source_type="runbook")
        + _seed_chunks(2, source_type="cti_report"),
    )
    node = KnowledgeSearchNode(client=fake)

    out = await node.run(
        KnowledgeSearchInput(query="C2", top_k=10, source_type="cti_report"),
        _ctx(),
    )
    assert fake.search_calls[-1]["source_type"] == "cti_report"
    assert all(r.source_type == "cti_report" for r in out.results)
    assert len(out.results) == 2


async def test_search_empty_query_short_circuits_without_hitting_client():
    """An empty query string must NOT round-trip the client -- we save the
    network call and match what the backend RAG would return anyway."""
    fake = FakeKnowledgeClient()
    fake.seed(_seed_chunks(5))
    node = KnowledgeSearchNode(client=fake)

    out = await node.run(KnowledgeSearchInput(query=""), _ctx())
    assert out.results == []
    assert fake.search_calls == []  # Critical: no client call.
    assert out.query == ""  # Echo preserved even on short-circuit.


async def test_search_echoes_query_in_output_for_traceability():
    """The output carries the input query verbatim so downstream pipeline
    steps (and audit logs) can correlate results with the originating query."""
    fake = FakeKnowledgeClient()
    fake.seed(_seed_chunks(1))
    node = KnowledgeSearchNode(client=fake)

    query = "powershell encoded command base64"
    out = await node.run(KnowledgeSearchInput(query=query), _ctx())
    assert out.query == query


# ---------------------------------------------------------------------------
# End-to-end via Runner (validates middleware pipeline + dict payload path)
# ---------------------------------------------------------------------------


async def test_search_end_to_end_through_runner_with_fake_client():
    """The Runner validates dict payloads against input_schema and runs the
    middleware chain. The Node must work transparently inside it."""
    fake = FakeKnowledgeClient()
    fake.seed(_seed_chunks(2))
    node = KnowledgeSearchNode(client=fake)

    out = await Runner().execute(
        node,
        {"query": "ransomware playbook", "top_k": 5},
        _ctx(),
    )
    assert isinstance(out, KnowledgeSearchOutput)
    assert out.query == "ransomware playbook"
    assert len(out.results) == 2
    assert fake.search_calls[-1]["query"] == "ransomware playbook"


# ---------------------------------------------------------------------------
# Registry registration
# ---------------------------------------------------------------------------


def test_search_node_is_registered():
    """The @NodeRegistry.register decorator must publish the Node under its
    stable id so the workflow compiler can resolve it from a YAML reference."""
    assert NodeRegistry.get("knowledge.search") is KnowledgeSearchNode


def test_search_node_falls_back_to_factory_when_no_client_given():
    """The executor instantiates Nodes with no constructor args
    (``node_cls()``); the Node must default to a working client via the
    class-level ``client_factory`` hook so the no-arg path is safe."""
    node = KnowledgeSearchNode()  # No client argument.
    # The default factory yields a FakeKnowledgeClient -- safe by default
    # so a misconfigured prod env doesn't accidentally hit a real backend.
    assert isinstance(node._client, FakeKnowledgeClient)
