"""Tests for the single-rule telemetry validator (#113 back half, slice 2).

Runs against the integration nodes' deterministic mock fixtures
(``BTAGENT_MOCK_CONNECTORS=true``): a transpilable rule collects per-backend
hit counts; transpile failures and unsupported backend names degrade to
per-backend errors; the verdict property discriminates matched / clean /
error.
"""

from __future__ import annotations

import pytest

from btagent_engine.hunting.rule_validator import (
    BackendValidation,
    RuleValidationResult,
    validate_rule,
)
from btagent_engine.node import NodeContext

_VALID_RULE = """\
title: Test Encoded PowerShell
id: 00000000-0000-4000-8000-000000000113
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: '-EncodedCommand'
  condition: selection
level: medium
"""

_INVALID_RULE = "just: a\nplain: mapping\n"


@pytest.fixture(autouse=True)
def _mock_connectors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")


def _ctx() -> NodeContext:
    return NodeContext(run_id="vrun_test01", org_id="org_default")


async def test_valid_rule_collects_hits_per_backend() -> None:
    result = await validate_rule(_VALID_RULE, ["splunk", "crowdstrike"], _ctx())
    assert {b.backend for b in result.backends} == {"splunk", "crowdstrike"}
    for b in result.backends:
        assert b.error is None
        assert b.query
    # Mock fixtures return events for any query — the verdict reads matched.
    assert result.total_hits > 0
    assert result.verdict == "matched"


async def test_default_fanout_covers_all_supported_backends() -> None:
    result = await validate_rule(_VALID_RULE, None, _ctx())
    assert {b.backend for b in result.backends} == {
        "splunk",
        "sentinel",
        "elastic",
        "crowdstrike",
    }


async def test_invalid_rule_degrades_to_per_backend_errors() -> None:
    result = await validate_rule(_INVALID_RULE, ["splunk", "elastic"], _ctx())
    assert all(b.error and "transpile failed" in b.error for b in result.backends)
    assert result.total_hits == 0
    assert result.verdict == "error"


async def test_unsupported_backend_is_isolated_error() -> None:
    result = await validate_rule(_VALID_RULE, ["splunk", "defender"], _ctx())
    by_name = {b.backend: b for b in result.backends}
    assert by_name["defender"].error == "unsupported backend 'defender'"
    assert by_name["splunk"].error is None
    # One good backend with hits still reads matched.
    assert result.verdict == "matched"


def test_verdict_clean_when_no_hits_and_not_all_errors() -> None:
    result = RuleValidationResult(
        validated_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
        lookback_hours=24,
        backends=[
            BackendValidation(backend="splunk", query="q", hit_count=0),
            BackendValidation(backend="elastic", error="execution failed: down"),
        ],
    )
    assert result.verdict == "clean"
