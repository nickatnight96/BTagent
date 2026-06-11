"""Tests for run_pack: pack execution through the mock integration nodes (#112)."""

from __future__ import annotations

import pytest
from btagent_shared.types.enums import Severity

from btagent_engine import NodeContext
from btagent_engine.hunting import (
    HuntPack,
    HuntPackRule,
    PackRunResult,
    SigmaHit,
    load_builtin_pack,
    run_pack,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_hunt", org_id="org_default")


@pytest.fixture(autouse=True)
def _enable_mock(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    yield


_SPRAY_YAML = """\
title: Failed Network Logon Spray Candidate
id: 00000000-0000-4000-8000-000000000010
logsource:
  product: windows
  service: security
detection:
  sel:
    EventID: 4625
    LogonType: 3
  condition: sel
level: medium
tags:
  - attack.t1110.003
"""

# Valid YAML, valid-enough Sigma to load, but uses the deprecated pipe
# aggregation syntax pySigma rejects -> errors on every backend at transpile.
_BROKEN_YAML = """\
title: Deliberately Broken Aggregation Rule
id: 00000000-0000-4000-8000-000000000011
logsource:
  product: windows
  service: security
detection:
  sel1:
    EventID: 4624
  sel2:
    EventID: 4625
  condition: sel1 | near sel2
level: low
"""


_PS_YAML = """\
title: Encoded PowerShell Command Line
id: 00000000-0000-4000-8000-000000000012
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    Image|endswith: '\\\\powershell.exe'
    CommandLine|contains: ' -enc '
  condition: sel
level: high
tags:
  - attack.t1059.001
"""


def _ps_rule(**overrides) -> HuntPackRule:
    base = dict(
        id="rule_ps",
        title="Encoded PowerShell Command Line",
        sigma_yaml=_PS_YAML,
        logsource={"category": "process_creation", "product": "windows"},
        mitre_techniques=["T1059.001"],
        severity=Severity.HIGH,
    )
    base.update(overrides)
    return HuntPackRule(**base)


def _spray_rule(**overrides) -> HuntPackRule:
    base = dict(
        id="rule_spray",
        title="Failed Network Logon Spray Candidate",
        sigma_yaml=_SPRAY_YAML,
        logsource={"product": "windows", "service": "security"},
        mitre_techniques=["T1110.003"],
        severity=Severity.MEDIUM,
    )
    base.update(overrides)
    return HuntPackRule(**base)


def _pack(rules: list[HuntPackRule]) -> HuntPack:
    return HuntPack(id="hpack_test", name="Test Pack", version="0.1.0", rules=rules)


# --- happy path across all four mock backends ---


async def test_run_pack_returns_hits_on_all_backends():
    result = await run_pack(
        _pack([_spray_rule()]),
        ["splunk", "sentinel", "elastic", "crowdstrike"],
        _ctx(),
    )

    assert isinstance(result, PackRunResult)
    assert result.run_id.startswith("hrun_")
    assert result.pack_id == "hpack_test"
    assert result.completed_at is not None
    assert result.error_count == 0
    assert len(result.rule_results) == 1

    by_backend = {b.backend: b for b in result.rule_results[0].backend_results}
    assert set(by_backend) == {"splunk", "sentinel", "elastic", "crowdstrike"}
    # The transpiled query is recorded per backend.
    assert "EventCode=4625" in by_backend["splunk"].query
    assert by_backend["sentinel"].query.startswith("DeviceLogonEvents")
    # Splunk's auth fixture matches the security/logon query keywords.
    assert by_backend["splunk"].hit_count >= 1
    assert all(b.hit_count == len(b.hits) for b in by_backend.values())


async def test_hits_propagate_rule_severity_techniques_and_run_id():
    result = await run_pack(_pack([_spray_rule()]), ["splunk"], _ctx())

    hits = result.all_hits
    assert hits, "expected the mock Splunk auth fixture to produce hits"
    for hit in hits:
        assert isinstance(hit, SigmaHit)
        assert hit.source == "sigma_pack"
        assert hit.source_run_id == result.run_id
        assert hit.pack_id == "hpack_test"
        assert hit.rule_id == "rule_spray"
        assert hit.backend == "splunk"
        assert hit.severity == Severity.MEDIUM
        assert hit.mitre_techniques == ["T1110.003"]
        assert hit.raw  # raw backend event kept verbatim


async def test_hits_extract_entities_and_observable_from_raw_event():
    result = await run_pack(_pack([_spray_rule()]), ["splunk"], _ctx())

    hit = result.all_hits[0]
    # Mock Splunk network fixture: host=fw-edge-01, src_ip=10.1.42.17.
    kinds = {e.kind: e.value for e in hit.entities}
    assert kinds["host"] == "fw-edge-01"
    assert hit.observable == "10.1.42.17"
    assert hit.observable_type == "ip"


async def test_sentinel_and_elastic_hits_extract_their_dialects():
    # Process-creation rule: Sentinel's XDR-table KQL matches the mock
    # process fixture; the spray rule covers Elastic's nested ECS shape.
    result = await run_pack(_pack([_ps_rule(), _spray_rule()]), ["sentinel", "elastic"], _ctx())
    by_rule = {r.rule_id: r for r in result.rule_results}

    # Sentinel process fixture row: Computer + Account + CommandLine.
    sentinel_hit = next(
        b for b in by_rule["rule_ps"].backend_results if b.backend == "sentinel"
    ).hits[0]
    kinds = {e.kind: e.value for e in sentinel_hit.entities}
    assert kinds["host"] == "WS-JSMITH-PC"
    assert "jsmith" in kinds["user"]
    assert "powershell" in sentinel_hit.summary.lower()  # CommandLine -> summary

    # Elastic filebeat fixture: nested host.name + user.name under _source.
    elastic_hit = next(
        b for b in by_rule["rule_spray"].backend_results if b.backend == "elastic"
    ).hits[0]
    kinds = {e.kind: e.value for e in elastic_hit.entities}
    assert kinds["host"] == "WS-JSMITH-PC"
    assert kinds["user"] == "jsmith"


# --- error isolation ---


async def test_broken_rule_yields_errors_but_other_rules_still_run():
    pack = _pack(
        [
            HuntPackRule(
                id="rule_broken",
                title="Deliberately Broken Aggregation Rule",
                sigma_yaml=_BROKEN_YAML,
                severity=Severity.LOW,
            ),
            _spray_rule(),
        ]
    )
    result = await run_pack(pack, ["splunk", "elastic"], _ctx())

    by_rule = {r.rule_id: r for r in result.rule_results}
    broken = by_rule["rule_broken"]
    # Every backend of the broken rule carries a typed transpile error...
    assert set(broken.errors) == {"splunk", "elastic"}
    assert all(b.query is None and not b.hits for b in broken.backend_results)
    # ...and the healthy rule still executed and produced hits.
    good = by_rule["rule_spray"]
    assert good.errors == {}
    assert good.hit_count >= 1
    assert result.error_count == 2


async def test_backend_execution_failure_is_isolated(monkeypatch):
    async def _boom(self, input, ctx):
        raise RuntimeError("splunk unreachable")

    from btagent_engine.integrations.splunk import SplunkSearchNode

    monkeypatch.setattr(SplunkSearchNode, "run", _boom)

    result = await run_pack(_pack([_spray_rule()]), ["splunk", "elastic"], _ctx())
    by_backend = {b.backend: b for b in result.rule_results[0].backend_results}

    assert "splunk unreachable" in by_backend["splunk"].error
    assert by_backend["splunk"].query is not None  # transpile succeeded; exec failed
    assert by_backend["elastic"].error is None
    assert by_backend["elastic"].hit_count >= 1


# --- disabled rules / argument validation ---


async def test_disabled_rules_are_skipped_and_reported():
    pack = _pack([_spray_rule(), _spray_rule(id="rule_off", enabled=False)])
    result = await run_pack(pack, ["splunk"], _ctx())

    assert result.skipped_rule_ids == ["rule_off"]
    assert [r.rule_id for r in result.rule_results] == ["rule_spray"]


async def test_run_pack_rejects_unknown_or_empty_backends():
    with pytest.raises(ValueError, match="unknown backends"):
        await run_pack(_pack([_spray_rule()]), ["qradar"], _ctx())  # type: ignore[list-item]
    with pytest.raises(ValueError, match="at least one backend"):
        await run_pack(_pack([_spray_rule()]), [], _ctx())


# --- builtin pack end-to-end against mocks ---


async def test_builtin_pack_runs_end_to_end_on_mocks():
    pack = load_builtin_pack("windows_baseline")
    result = await run_pack(pack, ["splunk", "sentinel", "elastic", "crowdstrike"], _ctx())

    assert result.error_count == 0
    assert len(result.rule_results) == 4
    assert result.all_hits
    # Every backend result carries the transpiled query it ran.
    assert all(b.query for r in result.rule_results for b in r.backend_results)
    # CrowdStrike degrades to detections; severity still comes from the rule.
    cs_hits = [h for h in result.all_hits if h.backend == "crowdstrike"]
    assert cs_hits
    assert all(h.severity in set(Severity) for h in cs_hits)


# --- Elastic lookback wiring (Codex #198 P1) ------------------------------


@pytest.mark.asyncio
async def test_elastic_query_carries_lookback_timestamp_filter(monkeypatch):
    """The Elastic search must bound results by ``@timestamp >= now-{Nh}``.

    Without this, a 24-hour hunt scans the whole index and the ``size`` cap
    fills with arbitrary documents — emitting historical events as fresh
    findings and distorting noise baselines.
    """
    import btagent_engine.hunting.runner as runner

    captured: dict[str, object] = {}

    class _FakeNode:
        async def run(self, inp, _ctx):  # noqa: ANN001
            captured["query"] = inp.query
            captured["size"] = inp.size

            class _Out:
                hits: list[dict] = []  # noqa: RUF012

            return _Out()

    monkeypatch.setattr(runner, "ElasticSearchNode", _FakeNode)

    rule = HuntPackRule(
        id="hrule_x",
        title="x",
        file="x.yml",
        sigma_yaml="title: x\n",
        logsource={"category": "process_creation", "product": "windows"},
        mitre_techniques=["T1059"],
        severity=Severity.MEDIUM,
        enabled=True,
    )
    await runner._run_elastic(
        query='process.command_line: "powershell"',
        rule=rule,
        ctx=_ctx(),
        lookback_hours=24,
        max_hits=50,
    )

    q = captured["query"]
    assert isinstance(q, dict)
    assert "bool" in q and "filter" in q["bool"]
    filters = q["bool"]["filter"]
    # Both the query_string AND the @timestamp range must be present.
    assert any("query_string" in f for f in filters)
    assert any(
        "range" in f and f["range"].get("@timestamp", {}).get("gte") == "now-24h" for f in filters
    ), f"expected @timestamp gte now-24h in filters; got {filters!r}"
    assert captured["size"] == 50
