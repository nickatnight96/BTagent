"""End-to-end tests for the Sentinel KQL Query Node."""

from __future__ import annotations

import pytest

from btagent_engine import NodeContext, NodeRegistry, Runner
from btagent_engine.integrations.sentinel import (
    SentinelKQLQueryInput,
    SentinelKQLQueryNode,
    SentinelKQLQueryOutput,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_sentinel", org_id="org_default", investigation_id="inv_test")


@pytest.fixture(autouse=True)
def _enable_mock(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    yield


async def test_kql_query_returns_signin_rows_for_signin_query():
    out = await Runner().execute(
        SentinelKQLQueryNode(),
        SentinelKQLQueryInput(query="SigninLogs | where ResultType != 0"),
        _ctx(),
    )
    assert isinstance(out, SentinelKQLQueryOutput)
    assert len(out.rows) == 1
    assert out.rows[0]["UserPrincipalName"] == "jsmith@acme-corp.com"
    assert "UserPrincipalName" in out.column_names
    # column_names must mirror the row keys, in order
    assert out.column_names == list(out.rows[0].keys())


async def test_kql_query_returns_process_rows_for_securityevent_query():
    out = await Runner().execute(
        SentinelKQLQueryNode(),
        SentinelKQLQueryInput(query="SecurityEvent | where EventID == 4688"),
        _ctx(),
    )
    assert len(out.rows) == 1
    assert out.rows[0]["EventID"] == 4688
    assert "Computer" in out.column_names


async def test_kql_query_unknown_table_returns_empty_shape():
    """Queries that don't match any fixture fall through to empty rows + columns."""
    out = await Runner().execute(
        SentinelKQLQueryNode(),
        SentinelKQLQueryInput(query="SomeUnknownTable | take 10"),
        _ctx(),
    )
    assert out.rows == []
    assert out.column_names == []


async def test_kql_query_accepts_dict_payload_through_runner():
    out = await Runner().execute(
        SentinelKQLQueryNode(),
        {"query": "SigninLogs", "timespan_hours": 6},
        _ctx(),
    )
    assert len(out.rows) == 1


def test_kql_query_node_is_registered():
    assert NodeRegistry.get("integration.sentinel.kql_query") is SentinelKQLQueryNode


async def test_kql_query_raises_in_non_mock_mode(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    with pytest.raises(NotImplementedError, match="Sprint 2"):
        await SentinelKQLQueryNode().run(
            SentinelKQLQueryInput(query="SigninLogs"),
            _ctx(),
        )
