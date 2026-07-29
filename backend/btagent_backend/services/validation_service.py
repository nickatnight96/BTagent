"""Detection Validation Service — simulation-fixture slice (#118).

Orchestrates the replay of ``SimulationScenario`` fixtures through the
hunt pipeline and produces a deterministic ``ValidationReport``.

This is the *engine + report* layer only — no new API route, no migration,
no live Atomic Red Team / Caldera execution (that is deferred to the next
PR; this slice defines the report shape that wiring will fill).

Architecture
------------
``run_validation`` is the single public entry point.  It:

1. Resolves which packs to validate against (defaults to ``windows_baseline``).
2. Builds an in-process runner callable for each pack by parsing the pack's
   Sigma rules with pySigma and wrapping them in an async match function.
3. Calls :func:`btagent_shared.hunt.validation.replay_scenario` for each
   scenario, feeding each event's ``source_event_dict`` through the runner.
4. Calls :func:`btagent_shared.hunt.validation.build_report` to assemble the
   ``ValidationReport`` with per-technique ``CoverageResult`` objects.
5. Returns the ``ValidationReport`` — the caller owns persistence / emission.

The in-process runner (``_build_sigma_event_runner``) matches raw event dicts
against the Sigma rule's detection condition without hitting a SIEM backend.
It uses the same pySigma SigmaCollection/SigmaRule that the engine transpiler
uses, so the detection logic is production-faithful.

TODO (deferred — next PR: live ART/Caldera wiring)
---------------------------------------------------
* ``run_live_validation(scenarios, art_runner)`` — wraps a real Atomic Red
  Team / Caldera execution client; the client fires each technique, captures
  the resulting telemetry, and packages it as ``SimulatedAttackEvent`` dicts
  for replay through this same ``run_validation`` pipeline.  The report shape
  is the contract this PR defines.
* Persistence: write each ``ValidationReport`` to a new
  ``detection_validation_runs`` table so analysts can diff coverage over time.
* API route: ``POST /api/v1/validation/runs`` → trigger a run; results
  streamed via the existing WebSocket hub.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from typing import Any

from btagent_shared.hunt.validation import build_report, replay_scenario
from btagent_shared.types.detection_validation import (
    CoverageResult,
    EmulationRequest,
    SimulationScenario,
    TargetEnv,
    TechniqueVerdict,
    ValidationReport,
    ValidationSummary,
    ValidationVerdict,
)

logger = logging.getLogger("btagent.services.validation")

# Packs validated by default when the caller does not specify.
_DEFAULT_PACKS = ("windows_baseline",)


# ---------------------------------------------------------------------------
# Internal: in-process Sigma event matcher
# ---------------------------------------------------------------------------


def _as_bool(value: Any) -> bool | None:
    """Coerce an event field to a bool (``True``/``"true"``/``1``), else None."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
        return value.strip().lower() == "true"
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    return None


def _sigma_value_matches_event_field(
    sigma_val: Any,
    field_val: Any,
    modifier_names: list[str],
) -> bool:
    """Return True when *sigma_val* matches *field_val* under *modifiers*.

    Handles SigmaString (endswith / startswith / contains / exact), SigmaNumber
    (numeric equality) and SigmaBool (truthiness, so ``hostPID: true`` in a
    Kubernetes-audit rule matches a JSON ``true``).  Case-insensitive for string
    comparisons.
    """
    from sigma.types import SigmaBool, SigmaNumber, SigmaString

    plain = sigma_val.to_plain()

    if isinstance(sigma_val, SigmaBool):
        coerced = _as_bool(field_val)
        return coerced is not None and coerced is bool(plain)

    if isinstance(sigma_val, SigmaNumber):
        try:
            return int(field_val) == int(plain)
        except (TypeError, ValueError):
            return False

    if not isinstance(sigma_val, SigmaString):
        return False

    field_str = str(field_val).lower()
    plain_str = str(plain).lower()

    if "SigmaEndswithModifier" in modifier_names or (
        plain_str.startswith("*") and not plain_str.endswith("*")
    ):
        return field_str.endswith(plain_str.lstrip("*"))
    if "SigmaStartswithModifier" in modifier_names or (
        plain_str.endswith("*") and not plain_str.startswith("*")
    ):
        return field_str.startswith(plain_str.rstrip("*"))
    if "SigmaContainsModifier" in modifier_names or (
        plain_str.startswith("*") and plain_str.endswith("*")
    ):
        return plain_str.strip("*") in field_str
    return field_str == plain_str


def _match_detection_item(item: Any, event: dict[str, Any]) -> bool:
    """True if this SigmaDetectionItem fires on the event dict."""
    field = item.field
    if field is None:
        return False
    field_val = event.get(field)
    if field_val is None:
        return False
    modifier_names = [m.__name__ for m in item.modifiers]
    return any(_sigma_value_matches_event_field(v, field_val, modifier_names) for v in item.value)


def _match_detection(det: Any, event: dict[str, Any]) -> bool:
    """True if a pySigma ``SigmaDetection`` fires on the event dict.

    A detection's members are combined with the linking pySigma itself resolved
    (``item_linking``): a *mapping* detection ANDs its field/value items, while a
    *list-of-mappings* detection ORs its nested sub-detections (the shape used by
    the cloud packs, e.g. ``weakening: [{a: false}, {b: false}]``). Recursing on
    nested :class:`SigmaDetection` members is what keeps a list-of-mappings rule
    from raising ``AttributeError: 'SigmaDetection' object has no attribute
    'field'`` and sinking the whole replay run.
    """
    from sigma.conditions import ConditionOR

    members = list(getattr(det, "detection_items", []) or [])
    if not members:
        return False
    results = (
        _match_detection(m, event)
        if hasattr(m, "detection_items")
        else _match_detection_item(m, event)
        for m in members
    )
    return any(results) if getattr(det, "item_linking", None) is ConditionOR else all(results)


# Condition tokens: parentheses are their own tokens (they must NOT glue onto an
# identifier — that was the bug that made every parenthesised condition evaluate
# to False), everything else is a whitespace-delimited word.
_COND_TOKEN_RE = re.compile(r"\(|\)|[^\s()]+")


def _selector_matches(pattern: str, keys: list[str]) -> list[str]:
    """Detection names matched by a ``1 of``/``all of`` selector pattern."""
    if pattern.lower() == "them":
        return list(keys)
    regex = re.compile(re.escape(pattern).replace(r"\*", ".*") + "$", re.IGNORECASE)
    return [k for k in keys if regex.match(k)]


def _evaluate_condition(condition_str: str, detection_results: dict[str, bool]) -> bool:
    """Evaluate a Sigma condition expression against per-detection boolean results.

    A small recursive-descent parser with correct Sigma precedence
    (``not`` > ``and`` > ``or``), parentheses, identifier references, and the
    ``1 of <pattern>`` / ``all of <pattern>`` / ``... of them`` selector forms
    (usable as sub-expressions, not just as the whole condition).
    """
    tokens = _COND_TOKEN_RE.findall(condition_str.strip())
    keys = list(detection_results)

    def parse_or(pos: int) -> tuple[bool, int]:
        val, pos = parse_and(pos)
        while pos < len(tokens) and tokens[pos].lower() == "or":
            right, pos = parse_and(pos + 1)
            val = val or right
        return val, pos

    def parse_and(pos: int) -> tuple[bool, int]:
        val, pos = parse_unary(pos)
        while pos < len(tokens) and tokens[pos].lower() == "and":
            right, pos = parse_unary(pos + 1)
            val = val and right
        return val, pos

    def parse_unary(pos: int) -> tuple[bool, int]:
        if pos >= len(tokens):
            return False, pos
        tok = tokens[pos]
        if tok.lower() == "not":
            val, pos = parse_unary(pos + 1)
            return (not val), pos
        if tok == "(":
            val, pos = parse_or(pos + 1)
            if pos < len(tokens) and tokens[pos] == ")":
                pos += 1
            return val, pos
        # "1 of <sel>" / "all of <sel>" / "any of <sel>"
        if tok.lower() in {"1", "all", "any"} and pos + 2 < len(tokens):
            if tokens[pos + 1].lower() == "of":
                matched = _selector_matches(tokens[pos + 2], keys)
                if tok.lower() == "all":
                    val = bool(matched) and all(detection_results[k] for k in matched)
                else:
                    val = any(detection_results[k] for k in matched)
                return val, pos + 3
        return detection_results.get(tok, False), pos + 1

    result, _ = parse_or(0)
    return result


def _match_sigma_rule(sigma_rule: Any, event: dict[str, Any]) -> bool:
    """Return True if the pySigma SigmaRule fires on the event dict."""
    detection_results: dict[str, bool] = {
        name: _match_detection(det, event) for name, det in sigma_rule.detection.detections.items()
    }
    condition_str: str = sigma_rule.detection.condition[0]
    return _evaluate_condition(condition_str, detection_results)


def _build_sigma_event_runner(pack_name: str) -> Any:
    """Build and return an async event-matching callable for the named builtin pack.

    Loads the pack, pre-parses all enabled rules with pySigma, and returns
    a closure that matches a raw event dict against all rules in O(n_rules).

    Parameters
    ----------
    pack_name:
        A name recognised by :func:`btagent_engine.hunting.pack.load_builtin_pack`.

    Returns
    -------
    An async callable ``(event_dict) -> list[dict]`` where each dict in the
    result contains at minimum ``rule_id``, ``rule_title``, and
    ``mitre_techniques``.
    """
    from btagent_engine.hunting.pack import load_builtin_pack
    from sigma.collection import SigmaCollection

    pack = load_builtin_pack(pack_name)

    parsed: list[tuple[Any, Any]] = []
    for hunt_rule in pack.enabled_rules:
        try:
            col = SigmaCollection.from_yaml(hunt_rule.sigma_yaml)
            sigma_rule = col.rules[0]
            parsed.append((hunt_rule, sigma_rule))
        except Exception as exc:
            logger.warning(
                "Skipping rule %s in pack %s — pySigma parse error: %s",
                hunt_rule.id,
                pack_name,
                exc,
            )

    async def _runner(event_dict: dict[str, Any]) -> list[dict[str, Any]]:
        hits: list[dict[str, Any]] = []
        for hunt_rule, sigma_rule in parsed:
            try:
                fired = _match_sigma_rule(sigma_rule, event_dict)
            except Exception:  # noqa: BLE001 — one odd rule must not sink the run
                logger.warning(
                    "Rule %s in pack %s raised while matching an event; treated as no-hit",
                    hunt_rule.id,
                    pack_name,
                    exc_info=True,
                )
                continue
            if fired:
                hits.append(
                    {
                        "rule_id": hunt_rule.id,
                        "rule_title": hunt_rule.title,
                        "mitre_techniques": list(hunt_rule.mitre_techniques),
                        "severity": str(hunt_rule.severity),
                        "pack_id": pack.id,
                    }
                )
        return hits

    return _runner


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def run_validation(
    scenarios: list[SimulationScenario],
    packs: tuple[str, ...] | list[str] | None = None,
    *,
    run_id: str | None = None,
) -> ValidationReport:
    """Replay *scenarios* through the named packs and return a ValidationReport.

    Parameters
    ----------
    scenarios:
        One or more ``SimulationScenario`` objects to replay.  Each scenario
        is a named, MITRE-tagged list of ``SimulatedAttackEvent`` records.
    packs:
        Builtin pack names to validate against.  Defaults to
        ``("windows_baseline",)``.  Passing multiple packs merges their rules
        into a single runner so one event can fire rules across packs.
    run_id:
        Optional caller-supplied run identifier.  When omitted, one is
        generated.

    Returns
    -------
    ValidationReport
        Deterministic coverage report.  The report is a returned value in
        this slice — persistence is deferred to the live ART/Caldera PR.
    """
    from btagent_shared.utils.ids import generate_id as _gen_id

    effective_packs = list(packs) if packs else list(_DEFAULT_PACKS)
    effective_run_id = run_id or _gen_id("valrun")

    if not scenarios:
        raise ValueError("at least one SimulationScenario is required")

    logger.info(
        "Starting validation run %s: %d scenario(s), packs=%s",
        effective_run_id,
        len(scenarios),
        effective_packs,
    )

    # Build one runner per pack and merge hits across all packs.
    runners = [_build_sigma_event_runner(p) for p in effective_packs]

    async def _merged_runner(event_dict: dict[str, Any]) -> list[dict[str, Any]]:
        all_hits: list[dict[str, Any]] = []
        for runner in runners:
            all_hits.extend(await runner(event_dict))
        return all_hits

    # Replay all scenarios.
    all_replay = []
    for scenario in scenarios:
        result = await replay_scenario(scenario, _merged_runner)
        all_replay.append(result)

    report = build_report(
        run_id=effective_run_id,
        scenarios=scenarios,
        replay_results_per_scenario=all_replay,
        generated_at=datetime.now(UTC),
    )

    logger.info(
        "Validation run %s complete: detected_pct=%.1f%% techniques=%d gaps=%s",
        effective_run_id,
        report.summary.detected_pct,
        report.summary.total_techniques,
        report.summary.gaps or "none",
    )

    return report


def build_emulation_report(
    *,
    run_id: str,
    request: EmulationRequest,
    verdict: TechniqueVerdict,
    generated_at: datetime,
) -> ValidationReport:
    """Fold a single-technique emulation ``verdict`` into a ``ValidationReport``.

    Maps the orchestrator's :class:`TechniqueVerdict` onto the same report shape
    the in-process replay path produces so persistence and the API are uniform.
    A verdict counts as "detected" coverage only when it is ``validated`` — a
    ``wrong_severity`` / ``late`` / ``silent_gap`` / ``errored`` verdict leaves
    the technique as a gap so it surfaces to analysts.
    """
    return build_multi_emulation_report(
        run_id=run_id,
        target_env=request.target_env,
        verdicts=[verdict],
        generated_at=generated_at,
    )


def build_multi_emulation_report(
    *,
    run_id: str,
    target_env: TargetEnv,
    verdicts: list[TechniqueVerdict],
    generated_at: datetime,
) -> ValidationReport:
    """Fold one *or more* technique verdicts into a single ``ValidationReport``.

    Used by the #113 merge closed loop, where a merged rule may carry several
    ATT&CK techniques and each one is emulated (sandbox-gated) in turn: the run
    history then holds ONE row covering every technique the rule claims, which
    is what the coverage map reads for staleness. Scoring per technique is the
    same as the single-verdict path — only ``validated`` counts as detected.
    """
    if not verdicts:
        raise ValueError("build_multi_emulation_report needs at least one verdict")

    coverage: list[CoverageResult] = []
    gaps: list[str] = []
    detected_count = 0
    for verdict in verdicts:
        detected = 1 if verdict.verdict == ValidationVerdict.VALIDATED else 0
        detected_count += detected
        if not detected:
            gaps.append(verdict.technique_id)
        coverage.append(
            CoverageResult(
                technique_id=verdict.technique_id,
                total_simulated=1,
                detected=detected,
                missed=0 if detected else 1,
                false_positives=0,
                rules_fired=[f.rule_id for f in verdict.fired_rules],
                rules_expected_but_missed=list(verdict.coverage_delta.missing_rules),
            )
        )

    summary = ValidationSummary(
        detected_pct=round(100.0 * detected_count / len(verdicts), 1),
        total_techniques=len(verdicts),
        gaps=gaps,
    )
    return ValidationReport(
        run_id=run_id,
        scenarios_run=len(verdicts),
        coverage_by_technique=coverage,
        summary=summary,
        generated_at=generated_at,
        emulation_target_env=target_env,
        verdicts=list(verdicts),
    )
