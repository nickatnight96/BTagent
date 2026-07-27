"""ValidationOrchestrator + sandbox-policy tests (#118).

Covers the guardrailed trigger -> observe -> score -> report loop and — most
importantly — proves the sandbox re-assertion refuses a non-sandbox target
BEFORE any emulator method runs. The mock end-to-end path fires ZERO real
techniques (every emulator result carries ``executed=False``).
"""

from __future__ import annotations

import pytest
from btagent_shared.security.sandbox import (
    APPROVED_SANDBOX_ENVS,
    SandboxViolationError,
    evaluate_sandbox_target,
    is_approved_sandbox,
    require_sandbox,
)
from btagent_shared.types.detection_validation import (
    EmulationRequest,
    TargetEnv,
    ValidationVerdict,
)
from btagent_shared.types.enums import Severity

from btagent_agents.mcp.servers import atomic_red_team_mcp as art
from btagent_agents.validation.orchestrator import (
    ObservedFiring,
    TriggerResult,
    ValidationOrchestrator,
)


@pytest.fixture(autouse=True)
def _clean_ledgers() -> None:
    art.MOCK_ATOMIC_LEDGER.clear()
    art.MOCK_DETECTION_LEDGER.clear()


# --------------------------------------------------------------------------- #
# Sandbox policy (pure)
# --------------------------------------------------------------------------- #


class TestSandboxPolicy:
    def test_only_sandbox_approved(self) -> None:
        assert APPROVED_SANDBOX_ENVS == frozenset({TargetEnv.SANDBOX})
        assert is_approved_sandbox(TargetEnv.SANDBOX) is True
        assert is_approved_sandbox("sandbox") is True

    @pytest.mark.parametrize("bad", ["production", "staging", "unknown", "", "nonsense", None])
    def test_non_sandbox_denied(self, bad: object) -> None:
        assert is_approved_sandbox(bad) is False
        decision = evaluate_sandbox_target(bad)
        assert decision.denied is True
        assert decision.approved is False
        assert decision.reason  # audit-safe explanation present

    def test_require_sandbox_raises_for_non_sandbox(self) -> None:
        with pytest.raises(SandboxViolationError):
            require_sandbox(TargetEnv.PRODUCTION)

    def test_require_sandbox_passes_for_sandbox(self) -> None:
        require_sandbox(TargetEnv.SANDBOX)  # no raise


# --------------------------------------------------------------------------- #
# Orchestrator — sandbox re-assertion (defence in depth)
# --------------------------------------------------------------------------- #


class TestOrchestratorSandboxGate:
    async def test_non_sandbox_refused_before_emulator_invoked(self) -> None:
        """The critical guardrail: a non-sandbox target raises BEFORE the
        trigger callable is ever awaited — no emulator method runs."""
        calls: list[str] = []

        async def spy_trigger(request: EmulationRequest) -> TriggerResult:
            calls.append(request.technique_id)
            raise AssertionError("emulator trigger must not be reached")

        orch = ValidationOrchestrator(trigger_fn=spy_trigger)
        with pytest.raises(SandboxViolationError):
            await orch.run(
                EmulationRequest(technique_id="T1059.001", target_env=TargetEnv.PRODUCTION)
            )
        assert calls == []  # emulator NEVER invoked
        # And nothing fired / was recorded.
        assert art.MOCK_ATOMIC_LEDGER == []
        assert art.MOCK_DETECTION_LEDGER == []

    @pytest.mark.parametrize("env", [TargetEnv.STAGING, TargetEnv.UNKNOWN])
    async def test_other_non_sandbox_envs_refused(self, env: TargetEnv) -> None:
        async def spy_trigger(request: EmulationRequest) -> TriggerResult:
            raise AssertionError("must not run")

        orch = ValidationOrchestrator(trigger_fn=spy_trigger)
        with pytest.raises(SandboxViolationError):
            await orch.run(EmulationRequest(technique_id="T1059.001", target_env=env))


# --------------------------------------------------------------------------- #
# Orchestrator — mock end-to-end verdicts
# --------------------------------------------------------------------------- #


class TestOrchestratorVerdicts:
    async def test_validated_happy_path_fires_nothing(self) -> None:
        orch = ValidationOrchestrator()
        verdict = await orch.run(
            EmulationRequest(
                technique_id="T1059.001",
                target_env=TargetEnv.SANDBOX,
                expected_severity=Severity.HIGH,
            )
        )
        assert verdict.verdict == ValidationVerdict.VALIDATED
        assert verdict.observed_severity == Severity.HIGH
        assert verdict.fired_rules and verdict.fired_rules[0].rule_id == "encoded_powershell"
        assert verdict.coverage_delta.missing_rules == []
        assert verdict.coverage_delta.last_validated is not None
        # Assert mock: the emulator recorded a run that executed nothing.
        assert art.MOCK_ATOMIC_LEDGER[0]["is_mock"] is True

    async def test_silent_gap_for_unknown_technique(self) -> None:
        orch = ValidationOrchestrator()
        verdict = await orch.run(
            EmulationRequest(technique_id="T9999", target_env=TargetEnv.SANDBOX)
        )
        assert verdict.verdict == ValidationVerdict.SILENT_GAP
        assert verdict.fired_rules == []
        assert verdict.coverage_delta.last_validated is None

    async def test_wrong_severity(self) -> None:
        orch = ValidationOrchestrator()
        verdict = await orch.run(
            EmulationRequest(
                technique_id="T1059.001",
                target_env=TargetEnv.SANDBOX,
                expected_severity=Severity.CRITICAL,  # mock fires 'high'
            )
        )
        assert verdict.verdict == ValidationVerdict.WRONG_SEVERITY
        assert verdict.observed_severity == Severity.HIGH

    async def test_late_when_sla_too_tight(self) -> None:
        orch = ValidationOrchestrator()
        verdict = await orch.run(
            EmulationRequest(
                technique_id="T1059.001",
                target_env=TargetEnv.SANDBOX,
                expected_severity=Severity.HIGH,
                latency_sla_seconds=1.0,  # mock firing is at 12s
            )
        )
        assert verdict.verdict == ValidationVerdict.LATE

    async def test_errored_when_trigger_raises_not_implemented(self) -> None:
        async def failing_trigger(request: EmulationRequest) -> TriggerResult:
            raise NotImplementedError("live executor not wired")

        orch = ValidationOrchestrator(trigger_fn=failing_trigger)
        verdict = await orch.run(
            EmulationRequest(technique_id="T1059.001", target_env=TargetEnv.SANDBOX)
        )
        assert verdict.verdict == ValidationVerdict.ERRORED

    async def test_injected_observer_shapes_verdict(self) -> None:
        """Full DI path: a custom observer drives the score without any MCP."""

        async def trigger(request: EmulationRequest) -> TriggerResult:
            return TriggerResult(
                run_id="art_x",
                technique_id=request.technique_id,
                expected_rule_id="my_rule",
                expected_severity=Severity.HIGH,
            )

        async def observe(technique_id: str, window: float) -> list[ObservedFiring]:
            return [
                ObservedFiring(
                    rule_id="my_rule",
                    technique_id=technique_id,
                    severity=Severity.HIGH,
                    latency_seconds=5.0,
                )
            ]

        orch = ValidationOrchestrator(trigger_fn=trigger, observe_fn=observe)
        verdict = await orch.run(
            EmulationRequest(
                technique_id="T1105",
                target_env=TargetEnv.SANDBOX,
                expected_severity=Severity.HIGH,
                latency_sla_seconds=60.0,
            )
        )
        assert verdict.verdict == ValidationVerdict.VALIDATED
        assert verdict.latency_seconds == 5.0
