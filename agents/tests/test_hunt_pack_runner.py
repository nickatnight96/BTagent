"""Tests for the Hunt Pack Runner: Sigma transpile + run orchestration (#112)."""

import pytest
from btagent_shared.types.huntpack import (
    HuntPackManifest,
    HuntRule,
    HuntRuleState,
    HuntSchedule,
    SiemBackend,
)

from btagent_agents.plugins.hunter import HuntPackRunner, SigmaCompiler
from btagent_agents.plugins.hunter.runner import ExecResult

_SIGMA = """
title: Encoded PowerShell
status: test
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-enc'
  condition: sel
"""


# --- SigmaCompiler ---


def test_compiler_transpiles_all_four_backends():
    compiler = SigmaCompiler()
    queries, errors = compiler.transpile(_SIGMA)
    assert errors == {}
    assert set(queries) == {
        SiemBackend.SPLUNK,
        SiemBackend.SENTINEL,
        SiemBackend.ELASTIC,
        SiemBackend.CROWDSTRIKE,
    }
    # Splunk SPL retains the field match
    assert "powershell.exe" in queries[SiemBackend.SPLUNK]


def test_compiler_targets_subset():
    compiler = SigmaCompiler()
    queries, errors = compiler.transpile(_SIGMA, [SiemBackend.SPLUNK])
    assert list(queries) == [SiemBackend.SPLUNK]


def test_compiler_invalid_yaml_reports_errors_for_all():
    compiler = SigmaCompiler()
    queries, errors = compiler.transpile("not: valid: sigma", [SiemBackend.SPLUNK])
    assert queries == {}
    assert SiemBackend.SPLUNK in errors


# --- HuntPackRunner ---


def _pack() -> HuntPackManifest:
    return HuntPackManifest(
        id="sigmahq-windows",
        version="1.0.0",
        source="sigmahq",
        rules=[
            HuntRule(
                id="rule_1",
                title="Encoded PowerShell",
                sigma_yaml=_SIGMA,
                mitre_techniques=["T1059.001"],
                severity="high",
            )
        ],
    )


class _FakeExecutor:
    """Returns a fixed count + hits regardless of backend/query."""

    def __init__(self, count: int, hits: list[dict]):
        self.count = count
        self.hits = hits
        self.calls: list[SiemBackend] = []

    async def __call__(self, backend, query, lookback) -> ExecResult:
        self.calls.append(backend)
        return ExecResult(count=self.count, hits=list(self.hits))


async def test_run_pack_emits_findings_and_updates_baseline():
    executor = _FakeExecutor(
        count=2,
        hits=[
            {
                "summary": "WS-1 ran encoded ps",
                "entities": [{"kind": "host", "value": "WS-1"}],
                "observables": [{"type": "process_name", "value": "powershell.exe"}],
            }
        ],
    )
    runner = HuntPackRunner(SigmaCompiler(), executor)
    pack = _pack()
    schedule = HuntSchedule(pack_id=pack.id, backends=[SiemBackend.SPLUNK])

    results = await runner.run_pack(pack, schedule, run_id="hrun_1")

    assert len(results) == 1
    res = results[0]
    # one hit per backend (only splunk targeted) -> one finding
    assert len(res.findings) == 1
    finding = res.findings[0]
    assert finding.source == "hunt_pack"
    assert finding.domain == "sigma"
    assert finding.technique_ids == ["T1059.001"]
    assert finding.evidence["rule_id"] == "rule_1"
    assert finding.evidence["run_id"] == "hrun_1"
    # baseline folded in this run's count
    assert res.updated_baseline.sample_count == 1
    assert res.updated_baseline.last_count == 2
    assert res.state == HuntRuleState.FIRING_AS_EXPECTED


async def test_run_pack_tuning_suppresses_matching_hit():
    executor = _FakeExecutor(
        count=1,
        hits=[
            {
                "summary": "approved admin host",
                "entities": [{"kind": "host", "value": "JUMP-1"}],
            }
        ],
    )
    runner = HuntPackRunner(SigmaCompiler(), executor)
    pack = _pack()
    # tune out the JUMP-1 host
    pack.rules[0].tuning = [{"entity_values": ["JUMP-1"]}]
    schedule = HuntSchedule(pack_id=pack.id, backends=[SiemBackend.SPLUNK])

    results = await runner.run_pack(pack, schedule, run_id="hrun_2")
    assert results[0].findings == []  # suppressed by tuning
    # but the hit still counts toward the baseline
    assert results[0].hit_count == 1


async def test_run_pack_marks_errored_on_transpile_failure():
    executor = _FakeExecutor(count=0, hits=[])
    runner = HuntPackRunner(SigmaCompiler(), executor)
    pack = HuntPackManifest(
        id="bad",
        version="1.0.0",
        source="private",
        rules=[HuntRule(id="r", title="bad", sigma_yaml="not: valid: sigma", severity="low")],
    )
    schedule = HuntSchedule(pack_id="bad", backends=[SiemBackend.SPLUNK])

    results = await runner.run_pack(pack, schedule, run_id="hrun_3")
    assert results[0].state == HuntRuleState.ERRORED
    assert results[0].findings == []
    # executor never called for an un-transpilable rule
    assert executor.calls == []
