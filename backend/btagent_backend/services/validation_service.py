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
    SimulationScenario,
    ValidationReport,
)

logger = logging.getLogger("btagent.services.validation")

# Packs validated by default when the caller does not specify.
_DEFAULT_PACKS = ("windows_baseline",)


# ---------------------------------------------------------------------------
# Internal: in-process Sigma event matcher
# ---------------------------------------------------------------------------


def _sigma_value_matches_event_field(
    sigma_val: Any,
    field_val: Any,
    modifier_names: list[str],
) -> bool:
    """Return True when *sigma_val* matches *field_val* under *modifiers*.

    Handles SigmaString (endswith / startswith / contains / exact) and
    SigmaNumber (numeric equality).  Case-insensitive for string comparisons.
    """
    from sigma.types import SigmaNumber, SigmaString

    plain = sigma_val.to_plain()

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


def _evaluate_condition(condition_str: str, detection_results: dict[str, bool]) -> bool:
    """Evaluate a Sigma condition expression against per-detection boolean results.

    Supports: AND / OR / NOT operators, parentheses, identifier references,
    and ``1 of <pattern>`` / ``all of <pattern>`` wildcard forms.
    """
    cond = condition_str.strip()

    m = re.match(r"^1\s+of\s+(\S+)\s*$", cond, re.IGNORECASE)
    if m:
        pat = re.compile(m.group(1).replace("*", ".*"), re.IGNORECASE)
        return any(v for k, v in detection_results.items() if pat.match(k))

    m = re.match(r"^all\s+of\s+(\S+)\s*$", cond, re.IGNORECASE)
    if m:
        pat = re.compile(m.group(1).replace("*", ".*"), re.IGNORECASE)
        keys = [k for k in detection_results if pat.match(k)]
        return bool(keys) and all(detection_results[k] for k in keys)

    def _eval(tokens: list[str], pos: int) -> tuple[bool, int]:
        val, pos = _eval_atom(tokens, pos)
        while pos < len(tokens) and tokens[pos].lower() == "and":
            right, pos = _eval_atom(tokens, pos + 1)
            val = val and right
        while pos < len(tokens) and tokens[pos].lower() == "or":
            right, pos = _eval_atom(tokens, pos + 1)
            val = val or right
        return val, pos

    def _eval_atom(tokens: list[str], pos: int) -> tuple[bool, int]:
        if pos >= len(tokens):
            return False, pos
        tok = tokens[pos]
        if tok.lower() == "not":
            v, pos = _eval_atom(tokens, pos + 1)
            return not v, pos
        if tok == "(":
            v, pos = _eval(tokens, pos + 1)
            if pos < len(tokens) and tokens[pos] == ")":
                pos += 1
            return v, pos
        return detection_results.get(tok, False), pos + 1

    tokens = re.findall(r"[()|\w*]+", cond)
    result, _ = _eval(tokens, 0)
    return result


def _match_sigma_rule(sigma_rule: Any, event: dict[str, Any]) -> bool:
    """Return True if the pySigma SigmaRule fires on the event dict."""
    detection_results: dict[str, bool] = {}
    for name, det in sigma_rule.detection.detections.items():
        detection_results[name] = all(
            _match_detection_item(item, event) for item in det.detection_items
        )
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
            if _match_sigma_rule(sigma_rule, event_dict):
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
