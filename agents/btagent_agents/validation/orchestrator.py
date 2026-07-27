"""Detection-validation orchestrator — trigger -> observe -> score -> report (#118).

The :class:`ValidationOrchestrator` runs one guardrailed adversary-emulation
loop for a technique:

1. **trigger** — fire the technique through an emulator (Atomic Red Team or
   Caldera), mock-first.
2. **observe** — poll a SIEM/EDR source for rule firings within the post-trigger
   latency SLA window.
3. **score** — compare observed firings against what was expected and assign a
   :class:`~btagent_shared.types.detection_validation.ValidationVerdict`.
4. **report** — return a :class:`TechniqueVerdict` (folded by the backend into a
   persisted :class:`ValidationReport`).

SAFETY
------
* **Sandbox re-assertion (defence in depth).** ``run`` calls
  :func:`btagent_shared.security.sandbox.require_sandbox` at the very top,
  BEFORE any emulator method is reachable. Even a direct in-process caller that
  bypassed the backend enforcement service cannot fire a technique against a
  non-sandbox target — the guard raises
  :class:`~btagent_shared.security.sandbox.SandboxViolationError` first.
* **Mock-first.** The default trigger/observe callables instantiate the
  emulator + detection MCP servers in mock mode; nothing real fires. All
  emulator I/O is injectable so tests can substitute spies and assert the loop
  never invokes an emulator on a denied target.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from btagent_shared.security.sandbox import require_sandbox
from btagent_shared.types.detection_validation import (
    CoverageDelta,
    EmulationRequest,
    RuleFiring,
    TechniqueVerdict,
    ValidationVerdict,
)
from btagent_shared.types.enums import Severity

logger = logging.getLogger("btagent.validation.orchestrator")


@dataclass
class ObservedFiring:
    """A normalised rule firing observed from the SIEM/EDR poll (internal)."""

    rule_id: str
    technique_id: str
    severity: Severity
    latency_seconds: float
    source: str = "mock_edr"
    rule_title: str = ""


# Injected phase callables — async so a live wiring can await network I/O.
TriggerFn = Callable[[EmulationRequest], Awaitable["TriggerResult"]]
ObserveFn = Callable[[str, float], Awaitable[list[ObservedFiring]]]


@dataclass
class TriggerResult:
    """Result of the trigger phase (what the emulator returned)."""

    run_id: str
    technique_id: str
    expected_rule_id: str | None = None
    expected_severity: Severity | None = None
    raw: dict = field(default_factory=dict)
    errored: bool = False
    error: str = ""


# --------------------------------------------------------------------------- #
# Default (mock-first) phase implementations
# --------------------------------------------------------------------------- #


async def _default_trigger(request: EmulationRequest) -> TriggerResult:
    """Fire the technique through the mock Atomic Red Team MCP server.

    This foundation slice triggers a *single technique* per validation run, so
    the default driver is the per-technique Atomic Red Team executor regardless
    of the requested ``emulator`` (Caldera's strength — multi-step operations —
    is exercised via its own connector; wiring profile-driven Caldera runs
    through the orchestrator is deferred). Mock-first: nothing real fires.
    """
    from btagent_agents.mcp.servers.atomic_red_team_mcp import AtomicRedTeamMCPServer

    server = AtomicRedTeamMCPServer(mock_mode=True)
    result = await server.run_atomic(request.technique_id)
    return TriggerResult(
        run_id=result.get("run_id", ""),
        technique_id=request.technique_id,
        expected_rule_id=result.get("expected_rule_id"),
        expected_severity=_coerce_severity(result.get("expected_severity")),
        raw=result,
    )


async def _default_observe(technique_id: str, window_seconds: float) -> list[ObservedFiring]:
    """Poll the mock SIEM/EDR detection bus for firings of *technique_id*.

    The mock emulators seed synthetic telemetry into ``MOCK_DETECTION_LEDGER``
    when they fire; this is the stand-in for a real SIEM/EDR MCP query. Live
    mode would swap this for a Splunk/CrowdStrike MCP poll over the same window.
    """
    from btagent_agents.mcp.servers.atomic_red_team_mcp import MOCK_DETECTION_LEDGER

    firings: list[ObservedFiring] = []
    for entry in MOCK_DETECTION_LEDGER:
        if entry.get("technique_id") != technique_id:
            continue
        firings.append(
            ObservedFiring(
                rule_id=str(entry.get("rule_id", "")),
                technique_id=technique_id,
                severity=_coerce_severity(entry.get("severity")) or Severity.MEDIUM,
                latency_seconds=float(entry.get("latency_seconds", 0.0)),
                source=str(entry.get("source", "mock_edr")),
                rule_title=str(entry.get("rule_title", "")),
            )
        )
    return firings


def _coerce_severity(value: object) -> Severity | None:
    if isinstance(value, Severity):
        return value
    if isinstance(value, str):
        try:
            return Severity(value.strip().lower())
        except ValueError:
            return None
    return None


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #


class ValidationOrchestrator:
    """Runs the sandbox-gated trigger -> observe -> score -> report loop."""

    def __init__(
        self,
        *,
        trigger_fn: TriggerFn | None = None,
        observe_fn: ObserveFn | None = None,
    ) -> None:
        self._trigger_fn: TriggerFn = trigger_fn or _default_trigger
        self._observe_fn: ObserveFn = observe_fn or _default_observe

    async def run(self, request: EmulationRequest) -> TechniqueVerdict:
        """Validate detection of ``request.technique_id`` end to end.

        Refuses (raises :class:`SandboxViolationError`) before any emulator is
        touched if ``request.target_env`` is not an approved sandbox.
        """
        # ---- GUARDRAIL: sandbox re-assertion BEFORE any emulator dispatch ----
        require_sandbox(request.target_env)

        # ---- trigger ----
        try:
            trigger = await self._trigger_fn(request)
        except NotImplementedError as exc:
            return self._errored(request, f"emulator trigger not implemented: {exc}")
        except Exception as exc:  # noqa: BLE001 - any trigger failure → errored verdict
            logger.exception("validation trigger failed for %s", request.technique_id)
            return self._errored(request, f"emulator trigger failed: {exc}")

        if trigger.errored:
            return self._errored(request, trigger.error or "emulator reported an error")

        # ---- observe ----
        try:
            observed = await self._observe_fn(request.technique_id, request.latency_sla_seconds)
        except Exception as exc:  # noqa: BLE001 - observation failure → errored verdict
            logger.exception("validation observe failed for %s", request.technique_id)
            return self._errored(request, f"detection observation failed: {exc}")

        # ---- score + report ----
        return self._score(request, trigger, observed)

    # ----- scoring -----

    def _score(
        self,
        request: EmulationRequest,
        trigger: TriggerResult,
        observed: list[ObservedFiring],
    ) -> TechniqueVerdict:
        expected_rule = trigger.expected_rule_id
        # Only firings matching this technique are relevant (observe already
        # filtered, but keep the invariant explicit).
        relevant = [f for f in observed if f.technique_id == request.technique_id]

        fired_rules = [
            RuleFiring(
                rule_id=f.rule_id,
                rule_title=f.rule_title,
                technique_id=f.technique_id,
                severity=f.severity,
                source=f.source,
                latency_seconds=f.latency_seconds,
            )
            for f in relevant
        ]
        fired_rule_ids = [f.rule_id for f in relevant]
        expected_rules = [expected_rule] if expected_rule else []
        missing = [r for r in expected_rules if r not in fired_rule_ids]

        # A firing "counts" for the pinned rule when an expected rule is known;
        # otherwise any matching firing counts.
        if expected_rule is not None:
            matching = [f for f in relevant if f.rule_id == expected_rule]
        else:
            matching = list(relevant)

        now = datetime.now(UTC)
        coverage_delta = CoverageDelta(
            technique_id=request.technique_id,
            expected_rules=expected_rules,
            fired_rules=fired_rule_ids,
            missing_rules=missing,
            last_validated=now if matching else None,
        )

        if not matching:
            verdict = ValidationVerdict.SILENT_GAP
            observed_sev = None
            latency = None
            detail = "No matching detection fired within the observation window."
        else:
            earliest = min(matching, key=lambda f: f.latency_seconds)
            latency = earliest.latency_seconds
            observed_sev = earliest.severity
            if latency > request.latency_sla_seconds:
                verdict = ValidationVerdict.LATE
                detail = (
                    f"Detection fired at {latency:.0f}s, past the "
                    f"{request.latency_sla_seconds:.0f}s SLA."
                )
            elif observed_sev != request.expected_severity:
                verdict = ValidationVerdict.WRONG_SEVERITY
                detail = (
                    f"Detection fired on time but at {observed_sev.value}, "
                    f"expected {request.expected_severity.value}."
                )
            else:
                verdict = ValidationVerdict.VALIDATED
                detail = "Expected detection fired on time at the expected severity."

        return TechniqueVerdict(
            technique_id=request.technique_id,
            verdict=verdict,
            emulator=request.emulator,
            expected_severity=request.expected_severity,
            observed_severity=observed_sev,
            latency_seconds=latency,
            latency_sla_seconds=request.latency_sla_seconds,
            fired_rules=fired_rules,
            coverage_delta=coverage_delta,
            detail=detail,
        )

    def _errored(self, request: EmulationRequest, detail: str) -> TechniqueVerdict:
        return TechniqueVerdict(
            technique_id=request.technique_id,
            verdict=ValidationVerdict.ERRORED,
            emulator=request.emulator,
            expected_severity=request.expected_severity,
            observed_severity=None,
            latency_seconds=None,
            latency_sla_seconds=request.latency_sla_seconds,
            fired_rules=[],
            coverage_delta=CoverageDelta(
                technique_id=request.technique_id,
                expected_rules=[],
                fired_rules=[],
                missing_rules=[],
                last_validated=None,
            ),
            detail=detail[:500],
        )
