"""End-to-end tests for the AbuseIPDB integration Node."""

from __future__ import annotations

import pytest

from btagent_engine import NodeContext, NodeRegistry, Runner
from btagent_engine.integrations.abuseipdb import (
    AbuseIPDBCheckInput,
    AbuseIPDBCheckNode,
    AbuseIPDBCheckOutput,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_abuseipdb", org_id="org_default", investigation_id="inv_test")


@pytest.fixture(autouse=True)
def _enable_mock(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    yield


async def test_abuseipdb_check_returns_known_malicious_record():
    out = await Runner().execute(
        AbuseIPDBCheckNode(),
        AbuseIPDBCheckInput(ip="185.220.101.42"),
        _ctx(),
    )
    assert isinstance(out, AbuseIPDBCheckOutput)
    assert out.seen is True
    assert out.abuse_confidence_score == 100
    assert out.total_reports >= 1000
    assert out.country_code == "DE"
    assert out.is_tor is True
    assert "Brute-Force" in out.categories


async def test_abuseipdb_check_returns_second_known_record():
    out = await Runner().execute(
        AbuseIPDBCheckNode(),
        AbuseIPDBCheckInput(ip="45.155.205.233"),
        _ctx(),
    )
    assert out.seen is True
    assert out.abuse_confidence_score >= 90
    assert out.country_code == "RU"
    assert out.is_tor is False


async def test_abuseipdb_check_returns_not_seen_for_unknown_ip():
    out = await Runner().execute(
        AbuseIPDBCheckNode(),
        AbuseIPDBCheckInput(ip="203.0.113.99"),
        _ctx(),
    )
    assert out.seen is False
    assert out.abuse_confidence_score == 0
    assert out.total_reports == 0
    assert out.categories == []


async def test_abuseipdb_check_accepts_dict_payload_through_runner():
    out = await Runner().execute(
        AbuseIPDBCheckNode(),
        {"ip": "185.220.101.42", "max_age_days": 30},
        _ctx(),
    )
    assert out.seen is True
    assert out.country_code == "DE"


async def test_abuseipdb_check_default_max_age_days():
    """``max_age_days`` defaults to 90 (the AbuseIPDB API default)."""
    payload = AbuseIPDBCheckInput(ip="185.220.101.42")
    assert payload.max_age_days == 90


def test_abuseipdb_check_node_is_registered():
    assert NodeRegistry.get("integration.abuseipdb.check") is AbuseIPDBCheckNode


async def test_abuseipdb_check_raises_in_non_mock_mode(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    with pytest.raises(NotImplementedError, match="Sprint 2"):
        await AbuseIPDBCheckNode().run(
            AbuseIPDBCheckInput(ip="8.8.8.8"),
            _ctx(),
        )
