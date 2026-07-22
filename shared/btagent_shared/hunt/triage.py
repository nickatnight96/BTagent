"""Pure clustering + suppression logic for the Hunt Triage Agent (#119).

No DB, no network, no LLM — these functions operate purely on
:mod:`btagent_shared.types.hunt_finding` models so they're trivially
unit-testable and reusable as an engine node body.

The clustering here is intentionally deterministic (a stable signature +
bucket) rather than a distance-based clusterer: triage needs a reproducible
"same noise as before" grouping that an analyst can reason about and write
a suppression against, not an opaque embedding cluster. A heavier
distance-based pass can layer on later without changing this contract.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from btagent_shared.types.enums import Severity
from btagent_shared.types.hunt_finding import (
    HuntFinding,
    SuppressionMatch,
)

# Severity ordering for picking a cluster's headline severity.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _entity_keys(finding: HuntFinding) -> tuple[str, ...]:
    """Stable, order-independent set of ``kind:value`` entity keys."""
    return tuple(sorted(f"{e.kind}:{e.value}" for e in finding.entities))


def _observable_keys(finding: HuntFinding) -> tuple[str, ...]:
    """Stable, order-independent set of ``type:value`` observable keys."""
    return tuple(sorted(f"{o.type}:{o.value}" for o in finding.observables))


def finding_signature(finding: HuntFinding) -> str:
    """Deterministic clustering key for a finding.

    Two findings collapse into the same cluster when they share domain,
    technique set, and entity *shape* (the set of entity kinds) — i.e. the
    "same kind of thing fired again on a different host." We deliberately
    key on entity *kinds* (not values) and on the full technique set so the
    cluster represents a repeating pattern, while the individual findings
    retain their per-host detail.
    """
    techniques = ",".join(sorted(finding.technique_ids))
    entity_kinds = ",".join(sorted({e.kind for e in finding.entities}))
    observable_types = ",".join(sorted({o.type for o in finding.observables}))
    return f"{finding.domain.value}|{techniques}|{entity_kinds}|{observable_types}"


def max_severity(findings: Sequence[HuntFinding]) -> Severity:
    """Highest severity across a group of findings (defaults to ``INFO``)."""
    if not findings:
        return Severity.INFO
    return max(findings, key=lambda f: _SEVERITY_RANK[f.severity]).severity


def union_techniques(findings: Iterable[HuntFinding]) -> list[str]:
    """Sorted union of technique ids across findings."""
    techniques: set[str] = set()
    for f in findings:
        techniques.update(f.technique_ids)
    return sorted(techniques)


def group_into_clusters(
    findings: Sequence[HuntFinding],
) -> dict[str, list[HuntFinding]]:
    """Bucket findings by :func:`finding_signature`.

    Returns an insertion-ordered mapping of signature → member findings so
    callers get stable cluster ordering (first-seen signature first).
    """
    clusters: dict[str, list[HuntFinding]] = {}
    for finding in findings:
        clusters.setdefault(finding_signature(finding), []).append(finding)
    return clusters


def cluster_reduction(findings: Sequence[HuntFinding]) -> float:
    """Fraction of findings collapsed by clustering, in ``[0, 1]``.

    ``1 - (num_clusters / num_findings)``. A higher number means the
    inbox got proportionally quieter. Returns ``0.0`` for an empty input.
    """
    if not findings:
        return 0.0
    num_clusters = len(group_into_clusters(findings))
    return 1.0 - (num_clusters / len(findings))


def match_for_cluster(findings: Sequence[HuntFinding]) -> SuppressionMatch:
    """Derive the default suppression criteria for a cluster of findings.

    A cluster groups findings sharing domain + technique set + entity
    *shape* (see :func:`finding_signature`), so the pattern-level match is
    ``domain AND technique overlap`` — deliberately *not* the concrete
    entity/observable values, which differ per member (that's why they
    clustered). This way the rule keeps suppressing the recurring pattern
    on hosts/users it hasn't seen yet. Callers still gate the result via
    :func:`is_overbroad` before persisting.
    """
    if not findings:
        return SuppressionMatch()
    return SuppressionMatch(
        domain=findings[0].domain,
        technique_ids=union_techniques(findings),
    )


def suppression_matches(match: SuppressionMatch, finding: HuntFinding) -> bool:
    """Does ``finding`` match the suppression criteria?

    AND across criteria types; OR (overlap) within a list criterion. An
    all-empty / all-``None`` match matches everything — callers should gate
    that via :func:`is_overbroad` before persisting.
    """
    if match.source is not None and finding.source != match.source:
        return False
    if match.domain is not None and finding.domain != match.domain:
        return False
    if match.technique_ids:
        if not (set(match.technique_ids) & set(finding.technique_ids)):
            return False
    if match.entity_values:
        finding_entity_vals = {e.value for e in finding.entities}
        if not (set(match.entity_values) & finding_entity_vals):
            return False
    if match.observable_values:
        finding_obs_vals = {o.value for o in finding.observables}
        if not (set(match.observable_values) & finding_obs_vals):
            return False
    if match.rule_ids:
        # Provenance-based criterion: pack-runner findings carry the
        # detection rule that produced them in evidence["rule_id"]. A
        # finding with no rule provenance can never match a rule_ids rule.
        if finding.evidence.get("rule_id") not in match.rule_ids:
            return False
    return True


def harmful_suppressions(
    rules: Sequence[SuppressionMatch],
    rule_ids: Sequence[str],
    promoted_findings: Sequence[HuntFinding],
) -> list[str]:
    """Return rule_ids whose match criteria would have matched any promoted finding.

    A suppression rule is "harmful" when it would have hidden a finding that an
    analyst has now confirmed as a real threat (i.e. promoted to an investigation).
    This pure helper is called by the service's ``promote_to_investigation`` to
    discover which active rules need their ``harmful_flag`` set.

    Args:
        rules: The ``SuppressionMatch`` criteria for each rule (parallel to rule_ids).
        rule_ids: The IDs of the rules to check (parallel to rules).
        promoted_findings: The findings just promoted into a confirmed investigation.

    Returns:
        Sorted list of rule IDs that match at least one promoted finding.
    """
    flagged: list[str] = []
    for rule_id, match in zip(rule_ids, rules):
        if any(suppression_matches(match, f) for f in promoted_findings):
            flagged.append(rule_id)
    return sorted(flagged)


def is_overbroad(
    match: SuppressionMatch,
    sample: Sequence[HuntFinding],
    *,
    max_match_fraction: float = 0.5,
    max_distinct_techniques: int = 5,
) -> tuple[bool, str]:
    """Heuristic guard against suppression rules that hide too much.

    A rule is over-broad when it specifies no narrowing criteria at all,
    or — measured against a representative ``sample`` of recent findings —
    it would match more than ``max_match_fraction`` of them or span more
    than ``max_distinct_techniques`` distinct techniques. Returns
    ``(is_overbroad, human_readable_reason)``.
    """
    has_any_criterion = any(
        [
            match.source is not None,
            match.domain is not None,
            bool(match.technique_ids),
            bool(match.entity_values),
            bool(match.observable_values),
            bool(match.rule_ids),
        ]
    )
    if not has_any_criterion:
        return True, "suppression specifies no criteria; it would match every finding"

    if not sample:
        return False, ""

    matched = [f for f in sample if suppression_matches(match, f)]
    fraction = len(matched) / len(sample)
    if fraction > max_match_fraction:
        return (
            True,
            f"suppression matches {fraction:.0%} of recent findings "
            f"(> {max_match_fraction:.0%} threshold)",
        )

    distinct_techniques = union_techniques(matched)
    if len(distinct_techniques) > max_distinct_techniques:
        return (
            True,
            f"suppression spans {len(distinct_techniques)} distinct techniques "
            f"(> {max_distinct_techniques} threshold)",
        )

    return False, ""
