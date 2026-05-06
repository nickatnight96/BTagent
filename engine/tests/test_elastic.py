"""End-to-end tests for the Elastic Search Node."""

from __future__ import annotations

import pytest

from btagent_engine import NodeContext, NodeRegistry, Runner
from btagent_engine.integrations.elastic import (
    ElasticSearchInput,
    ElasticSearchNode,
    ElasticSearchOutput,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_elastic", org_id="org_default", investigation_id="inv_test")


@pytest.fixture(autouse=True)
def _enable_mock(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    yield


async def test_elastic_search_returns_filebeat_hit_for_filebeat_index():
    out = await Runner().execute(
        ElasticSearchNode(),
        ElasticSearchInput(index="filebeat-*", query={"match_all": {}}),
        _ctx(),
    )
    assert isinstance(out, ElasticSearchOutput)
    assert out.total == 1
    assert out.hits[0]["_source"]["host"]["name"] == "WS-JSMITH-PC"


async def test_elastic_search_returns_packetbeat_hit_for_packetbeat_index():
    out = await Runner().execute(
        ElasticSearchNode(),
        ElasticSearchInput(index="packetbeat-2026.03.26", query={"match_all": {}}),
        _ctx(),
    )
    assert out.total == 1
    src = out.hits[0]["_source"]
    assert src["destination"]["ip"] == "198.51.100.23"


async def test_elastic_search_unknown_index_returns_empty_shape():
    """Indexes that don't match any fixture fall through to the empty shape."""
    out = await Runner().execute(
        ElasticSearchNode(),
        ElasticSearchInput(index="some-other-index-*", query={"match_all": {}}),
        _ctx(),
    )
    assert out.hits == []
    assert out.total == 0


async def test_elastic_search_size_caps_returned_hits_but_total_is_pre_cap():
    out = await Runner().execute(
        ElasticSearchNode(),
        ElasticSearchInput(index="filebeat-*", query={"match_all": {}}, size=1),
        _ctx(),
    )
    # only one fixture in the pool, so this is degenerate but exercises the path
    assert len(out.hits) == 1
    assert out.total == 1


async def test_elastic_search_accepts_dict_payload_through_runner():
    out = await Runner().execute(
        ElasticSearchNode(),
        {"index": "filebeat-*", "query": {"term": {"host.name": "WS-JSMITH-PC"}}},
        _ctx(),
    )
    assert out.total == 1


def test_elastic_search_node_is_registered():
    assert NodeRegistry.get("integration.elastic.search") is ElasticSearchNode


async def test_elastic_search_raises_in_non_mock_mode(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    with pytest.raises(NotImplementedError, match="Sprint 2"):
        await ElasticSearchNode().run(
            ElasticSearchInput(index="filebeat-*", query={"match_all": {}}),
            _ctx(),
        )
