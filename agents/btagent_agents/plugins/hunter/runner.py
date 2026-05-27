"""Hunt Pack Runner — compile → execute → triage one pack run (#112).

Orchestration only: it depends on an injected *executor* for the actual SIEM/
EDR queries (so the existing MCP connectors are pluggable and the runner is
unit-testable with a fake), and it emits :class:`RecordFindingRequest` payloads
rather than touching the DB itself. The scheduled arq job in the backend wires
a real executor in and persists the emitted findings into the #119 store.

Per #112 this is read-only / ``count-only`` work — no containment from a hunt
run.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol

from btagent_shared.hunt import huntpack as huntpack_logic
from btagent_shared.hunt import triage
from btagent_shared.types.hunt import HuntDomain, HuntFindingState, HuntSource
from btagent_shared.types.hunt_finding import (
    HuntEntity,
    HuntFinding,
    HuntObservable,
    RecordFindingRequest,
    SuppressionMatch,
)
from btagent_shared.types.huntpack import (
    HuntPackManifest,
    HuntRule,
    HuntRuleState,
    HuntSchedule,
    NoiseProfile,
    SiemBackend,
)

logger = logging.getLogger("btagent.hunter.runner")


@dataclass
class ExecResult:
    """Outcome of running one query on one backend.

    ``count`` is the total match count (used for the noise baseline, which may
    exceed ``len(hits)`` when the backend caps returned rows). ``hits`` are the
    individual matches that become findings — each a dict with optional
    ``entities`` / ``observables`` / ``summary`` keys.
    """

    count: int
    hits: list[dict] = field(default_factory=list)


class HuntExecutor(Protocol):
    """Runs a transpiled query on a backend over a lookback window."""

    async def __call__(
        self, backend: SiemBackend, query: str, lookback: timedelta
    ) -> ExecResult: ...


@dataclass
class RuleRunResult:
    """Per-rule outcome of a pack run."""

    rule_id: str
    state: HuntRuleState
    hit_count: int
    updated_baseline: NoiseProfile
    findings: list[RecordFindingRequest] = field(default_factory=list)
    errors: dict[SiemBackend, str] = field(default_factory=dict)


def _probe_finding(req: RecordFindingRequest) -> HuntFinding:
    """Wrap a candidate request as a throwaway HuntFinding for tuning checks.

    Lets us reuse the tested :func:`triage.suppression_matches` instead of
    re-implementing match semantics here.
    """
    now = datetime.now(UTC)
    return HuntFinding(
        id="hfnd_probe",
        org_id="org_probe",
        source=req.source,
        domain=req.domain,
        title=req.title,
        severity=req.severity,
        technique_ids=req.technique_ids,
        entities=req.entities,
        observables=req.observables,
        state=HuntFindingState.NEW,
        created_at=now,
        updated_at=now,
    )


class HuntPackRunner:
    """Compiles, executes, and triages a hunt pack against SIEM/EDR backends."""

    def __init__(self, compiler, executor: HuntExecutor) -> None:
        # ``compiler`` is a SigmaCompiler (duck-typed so tests can stub it
        # without importing pysigma).
        self._compiler = compiler
        self._executor = executor

    async def run_pack(
        self,
        pack: HuntPackManifest,
        schedule: HuntSchedule,
        *,
        run_id: str,
    ) -> list[RuleRunResult]:
        """Run every rule in ``pack`` across the schedule's backends.

        Compiles each rule (best-effort per backend), executes on each target,
        applies the rule's tuning suppression to hits, classifies the rule's
        state against its rolling baseline, and produces finding payloads for
        the surviving hits. The rule's ``noise_baseline`` / ``state`` /
        ``backend_queries`` are updated in place so the caller can persist them.
        """
        targets = schedule.backends or self._compiler.supported_backends
        results: list[RuleRunResult] = []

        for rule in pack.rules:
            results.append(
                await self._run_rule(rule, targets, schedule.lookback_window, pack, run_id)
            )
        return results

    async def _run_rule(
        self,
        rule: HuntRule,
        targets: list[SiemBackend],
        lookback: timedelta,
        pack: HuntPackManifest,
        run_id: str,
    ) -> RuleRunResult:
        queries, errors = self._compiler.transpile(rule.sigma_yaml, targets)
        rule.backend_queries = queries

        if not queries:
            rule.state = HuntRuleState.ERRORED
            return RuleRunResult(
                rule_id=rule.id,
                state=HuntRuleState.ERRORED,
                hit_count=0,
                updated_baseline=rule.noise_baseline,
                errors=errors,
            )

        total_count = 0
        findings: list[RecordFindingRequest] = []
        for backend, query in queries.items():
            try:
                exec_result = await self._executor(backend, query, lookback)
            except Exception as exc:
                logger.warning("Hunt query failed on %s for rule %s: %s", backend, rule.id, exc)
                errors[backend] = str(exc)
                continue
            total_count += exec_result.count
            for hit in exec_result.hits:
                req = self._hit_to_finding(rule, backend, hit, pack, run_id)
                if not self._suppressed_by_tuning(rule, req):
                    findings.append(req)

        state = huntpack_logic.classify_rule_state(rule.noise_baseline, total_count)
        rule.noise_baseline = huntpack_logic.update_baseline(rule.noise_baseline, total_count)
        # A per-backend execution error doesn't override a meaningful hit
        # classification; only flag ERRORED when nothing ran.
        if state == HuntRuleState.CLEAN and len(errors) == len(targets):
            state = HuntRuleState.ERRORED
        rule.state = state

        return RuleRunResult(
            rule_id=rule.id,
            state=state,
            hit_count=total_count,
            updated_baseline=rule.noise_baseline,
            findings=findings,
            errors=errors,
        )

    @staticmethod
    def _hit_to_finding(
        rule: HuntRule,
        backend: SiemBackend,
        hit: dict,
        pack: HuntPackManifest,
        run_id: str,
    ) -> RecordFindingRequest:
        entities = [HuntEntity(**e) for e in hit.get("entities", [])]
        observables = [HuntObservable(**o) for o in hit.get("observables", [])]
        summary = hit.get("summary") or rule.title
        return RecordFindingRequest(
            source=HuntSource.HUNT_PACK,
            domain=HuntDomain.SIGMA,
            title=f"{rule.title}: {summary}" if summary != rule.title else rule.title,
            description=hit.get("description", ""),
            severity=rule.severity,
            technique_ids=list(rule.mitre_techniques),
            entities=entities,
            observables=observables,
            evidence={
                "pack_id": pack.id,
                "pack_version": pack.version,
                "rule_id": rule.id,
                "backend": backend.value,
                "run_id": run_id,
                "raw": hit.get("raw", {}),
            },
        )

    @staticmethod
    def _suppressed_by_tuning(rule: HuntRule, req: RecordFindingRequest) -> bool:
        if not rule.tuning:
            return False
        probe = _probe_finding(req)
        # Coerce in case tuning arrived as raw dicts (e.g. loaded from JSON).
        rules = [SuppressionMatch.model_validate(t) for t in rule.tuning]
        return any(triage.suppression_matches(t, probe) for t in rules)


def make_mock_hunt_executor(hits_per_rule: int = 1) -> HuntExecutor:
    """A deterministic, count-only executor for dev / CI (no live SIEM).

    Returns a fixed small number of synthetic hits per query so the end-to-end
    pack-run → finding-persist → triage lifecycle is exercisable without a
    connected backend. Real MCP-backed count-only execution is wired by the
    scheduler job when ``BTAGENT_MOCK_CONNECTORS`` is off.
    """

    async def _executor(backend: SiemBackend, query: str, lookback: timedelta) -> ExecResult:
        hits = [
            {
                "summary": f"mock hit {i} on {backend.value}",
                "entities": [{"kind": "host", "value": f"mock-host-{i}"}],
                "raw": {"backend": backend.value, "query": query},
            }
            for i in range(hits_per_rule)
        ]
        return ExecResult(count=hits_per_rule, hits=hits)

    return _executor
