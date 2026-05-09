"""Elastic Security integration node.

Ports the simplest representative tool from the existing
``agents/btagent_agents/mcp/servers/elastic_mcp.py`` MCP server -- the
search across an index -- to the engine Node model.

The query is accepted as a raw Elasticsearch DSL ``dict`` rather than a
typed model: the canvas user is expected to know DSL, and pinning the
schema here would force this Node to drift every time Elastic adds a
clause type. Treat the dict as opaque payload.
"""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)


def _mock_mode_enabled() -> bool:
    """Resolve the mock-mode flag at call time so tests can flip it."""
    return os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Mock fixtures
# ---------------------------------------------------------------------------
# Two _source-shaped hits per index family. The fall-through (any
# unknown index) returns the empty shape -- this is the documented "no
# matching index" behaviour, distinct from "index found but query
# matched nothing" which we don't bother distinguishing in mock mode.

_MOCK_HITS_BY_INDEX_PREFIX: dict[str, list[dict[str, Any]]] = {
    "filebeat": [
        {
            "_index": "filebeat-2026.03.26",
            "_id": "es_doc_001",
            "_score": 12.4,
            "_source": {
                "@timestamp": "2026-03-26T08:22:05.000Z",
                "host": {"name": "WS-JSMITH-PC", "ip": "10.1.42.17"},
                "process": {"name": "powershell.exe", "pid": 7284},
                "user": {"name": "jsmith", "domain": "ACME"},
                "event": {"category": ["process"], "action": "process_created"},
            },
        },
    ],
    "packetbeat": [
        {
            "_index": "packetbeat-2026.03.26",
            "_id": "es_doc_010",
            "_score": 8.7,
            "_source": {
                "@timestamp": "2026-03-26T08:24:01.000Z",
                "source": {"ip": "10.1.42.17", "port": 51432},
                "destination": {"ip": "198.51.100.23", "port": 443},
                "network": {"transport": "tcp", "bytes": 154832},
                "host": {"name": "WS-JSMITH-PC"},
            },
        },
    ],
}


def _resolve_pool(index: str) -> list[dict[str, Any]]:
    """Match an index pattern (with or without wildcards / dates) to a fixture."""
    idx = index.lower()
    for prefix, pool in _MOCK_HITS_BY_INDEX_PREFIX.items():
        if idx.startswith(prefix):
            return pool
    return []


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ElasticSearchInput(BaseModel):
    # Allow arbitrary nested dicts in the query payload.
    model_config = ConfigDict(arbitrary_types_allowed=True)

    index: str = Field(
        ...,
        description="Elasticsearch index or index pattern (e.g. 'filebeat-*').",
        examples=["filebeat-*", "packetbeat-2026.03.*"],
    )
    query: dict[str, Any] = Field(
        ...,
        description="Raw Elasticsearch DSL query body. Treated as opaque by this Node.",
        examples=[{"match_all": {}}, {"term": {"host.name": "WS-JSMITH-PC"}}],
    )
    size: int = Field(
        default=100,
        ge=1,
        description="Maximum number of hits to return.",
    )


class ElasticSearchOutput(BaseModel):
    hits: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Matching hits in raw _source-wrapped form. Empty list when nothing matched.",
    )
    total: int = Field(
        default=0,
        description="Total matching documents (pre-size cap).",
    )


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


@NodeRegistry.register
class ElasticSearchNode(Node[ElasticSearchInput, ElasticSearchOutput]):
    """Run a DSL search against an Elasticsearch index."""

    meta = NodeMeta(
        id="integration.elastic.search",
        name="Elastic: Search",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
        description="Execute a raw Elasticsearch DSL query against an index "
        "or index pattern. Returns hits in their native "
        "_source-wrapped shape plus the total.",
    )
    input_schema = ElasticSearchInput
    output_schema = ElasticSearchOutput

    async def run(
        self,
        input: ElasticSearchInput,
        ctx: NodeContext,
    ) -> ElasticSearchOutput:
        if _mock_mode_enabled():
            pool = _resolve_pool(input.index)
            # ``total`` reflects the full mock pool size before size-capping --
            # mirrors how Elasticsearch's ``hits.total.value`` differs from
            # the length of ``hits.hits`` when ``size`` < total.
            total = len(pool)
            hits = pool[: input.size]
            return ElasticSearchOutput(hits=hits, total=total)

        raise NotImplementedError(
            "Elastic live API integration ships in Sprint 2 follow-up; "
            "set BTAGENT_MOCK_CONNECTORS=true to use mock fixtures."
        )
