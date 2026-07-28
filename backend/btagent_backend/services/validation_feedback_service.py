"""Phase-C closed-loop feedback for detection-validation runs (#118).

When a sandbox-gated emulation is scored (``TechniqueVerdict``), the verdict is
not just recorded — it *drives* the next detection-engineering action. This
module is the two best-effort feedback loops that close that loop, plus the
dispatcher that :mod:`validation_run_service` calls once a run is persisted:

* **(A) silent_gap → #113.** A ``silent_gap`` verdict means the emulation fired
  but NO detection rule caught the technique — a true coverage hole. We file a
  #113 draft detection proposal for the technique (via the same
  :func:`cti_detection_service.persist_proposals` path the clean-TTP hunt loop
  uses), so the gap lands in the analyst review queue as a rule to build.

* **(B) late / wrong_severity → #112.** The rule *did* fire, but too slowly
  (``late``) or at the wrong severity (``wrong_severity``) — a triage-quality
  gap, not a coverage gap. We file a #112 hunt-pack **tuning** suggestion (the
  same :class:`HuntPackSuggestionRow` review queue #120 promotes confirmed
  hunts through) carrying the offending rule plus the observed-vs-expected
  latency/severity, so an analyst can tune the detection.

Design invariants (shared by both loops)
----------------------------------------
* **Best-effort.** Every write is wrapped so a feedback failure can never sink
  the validation write that triggered it — the run row is already flushed by
  the time :func:`dispatch_validation_feedback` runs.
* **Org-scoped.** Every row is stamped with the run's ``org_id``; there is no
  cross-tenant proposal/suggestion.
* **Idempotent.** Re-scoring the same technique upserts in place rather than
  duplicating:
  - (A) is keyed on ``(org, source_stix_id="validation-gap--<tech>")`` — the
    ``persist_proposals`` upsert key — so a re-run refreshes the still-``proposed``
    draft and never clobbers an analyst decision.
  - (B) is keyed on ``(org, technique)`` via a deterministic shadow parent (see
    below) and the ``(org, proposal_id)`` unique index on the suggestion.

Migration-free reuse of the #112 suggestion queue
-------------------------------------------------
:class:`HuntPackSuggestionRow` carries a NOT-NULL FK to
``pattern_hunt_proposals`` (it was built for #120's hit→pack promotion). A
validation-origin tuning suggestion has no cross-investigation pattern proposal
behind it, and this PR adds no migration — so loop (B) first ensures a
deterministic **shadow** :class:`PatternHuntProposalRow` exists to satisfy that
FK. The shadow is created in the ``dismissed`` lifecycle state with a dedicated
``detection-tuning:<tech>`` cluster-id namespace, which keeps it fully inert to
the cross-investigation scanner: its cluster-id never collides with a real
weak-signal cluster (so suppression is a no-op for real proposals) and it
carries no ``outcome`` (so the rank-feedback query ignores it). It exists only
as the FK anchor for the reused suggestion queue.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from btagent_shared.types.detection_validation import (
    TechniqueVerdict,
    ValidationReport,
    ValidationVerdict,
)
from btagent_shared.utils.ids import generate_id
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("btagent.services.validation_feedback")

# (A) upsert namespace — one #113 draft per (org, technique) coverage gap.
SILENT_GAP_SOURCE_PREFIX = "validation-gap"
# (B) shadow-parent cluster namespace — one tuning suggestion per (org, technique).
TUNING_CLUSTER_PREFIX = "detection-tuning"
# Verdicts that route to loop (B).
_TUNING_VERDICTS = frozenset({ValidationVerdict.LATE, ValidationVerdict.WRONG_SEVERITY})


def _utcnow() -> datetime:
    return datetime.now(UTC)


# --------------------------------------------------------------------------- #
# (A) silent_gap → #113 detection proposal
# --------------------------------------------------------------------------- #


def _gap_sigma_skeleton(technique_id: str, detail: str) -> str:
    """A reviewable Sigma skeleton for a silent-gap draft proposal.

    Deliberately a placeholder (like the clean-hunt draft path): the value is
    surfacing the *gap* into the #113 queue with the technique tagged, not
    shipping a finished rule. A detection engineer fills the selection before
    accepting.
    """
    tag = technique_id.lower().replace(".", "_")
    return (
        f"title: {technique_id} — silent detection gap (from validation)\n"
        "status: experimental\n"
        "description: >-\n"
        f"  A sandbox emulation of {technique_id} fired but no detection rule "
        f"caught it. {detail or 'Build a detection so this technique alerts.'}\n"
        f"tags:\n  - attack.{tag}\n"
        "logsource:\n  category: process_creation\n"
        "detection:\n"
        "  selection:\n"
        "    # TODO(detection-engineering): translate the emulated technique\n"
        "    # into a concrete Sigma selection before accepting.\n"
        "    CommandLine|contains: PLACEHOLDER\n"
        "  condition: selection\n"
        "level: high\n"
    )


async def file_silent_gap_proposal(
    db: AsyncSession,
    *,
    org_id: str,
    technique_id: str,
    detail: str = "",
) -> tuple[int, int, int]:
    """File (or refresh) a #113 draft detection proposal for a silent-gap technique.

    Reuses :func:`cti_detection_service.persist_proposals`, so the row lands in
    the #113 review queue (state ``proposed``) and the ``(org, source_stix_id)``
    upsert makes this idempotent per ``(org, technique, source="validation-gap")``:
    a re-scored gap refreshes the still-proposed draft and an analyst-decided
    row is never overwritten. Returns the ``(created, updated, unchanged)``
    counts from the upsert. Flushes, never commits.
    """
    from btagent_shared.types.detection_proposal import DetectionProposal

    from btagent_backend.services.cti_detection_service import persist_proposals

    proposal = DetectionProposal(
        id=f"dprop-valgap-{technique_id}",
        source_stix_id=f"{SILENT_GAP_SOURCE_PREFIX}--{technique_id}",
        title=f"Detection gap: {technique_id} — emulation fired, no detection (silent gap)",
        sigma_yaml=_gap_sigma_skeleton(technique_id, detail),
        technique_ids=[technique_id],
        confidence=0.45,
        rationale=(
            f"A sandbox adversary-emulation of {technique_id} fired but NO detection "
            "rule caught it within the observation window (silent gap). Filing a draft "
            f"detection so the technique alerts without an emulation. {detail}".strip()
        ),
        generated_at=_utcnow(),
    )
    counts = await persist_proposals(db, org_id=org_id, proposals=[proposal])
    logger.info(
        "silent-gap #113 proposal filed for %s (org=%s): created=%d updated=%d unchanged=%d",
        technique_id,
        org_id,
        *counts,
    )
    return counts


# --------------------------------------------------------------------------- #
# (B) late / wrong_severity → #112 hunt-pack tuning suggestion
# --------------------------------------------------------------------------- #


async def _ensure_tuning_shadow_proposal(
    db: AsyncSession,
    *,
    org_id: str,
    technique_id: str,
) -> str:
    """Return the id of the deterministic shadow pattern-proposal for a technique.

    The shadow exists only to satisfy the NOT-NULL FK on
    :class:`HuntPackSuggestionRow` migration-free (see the module docstring). It
    is created once per ``(org, technique)`` in the ``dismissed`` state with the
    ``detection-tuning:<tech>`` cluster namespace so the cross-investigation
    scanner ignores it entirely.
    """
    from btagent_shared.types.hunt import HuntInput
    from btagent_shared.types.pattern_hunt import ProposalState

    from btagent_backend.db.models_pattern import PatternHuntProposalRow

    cluster_id = f"{TUNING_CLUSTER_PREFIX}:{technique_id}"
    existing = (
        await db.execute(
            select(PatternHuntProposalRow).where(
                PatternHuntProposalRow.org_id == org_id,
                PatternHuntProposalRow.cluster_id == cluster_id,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing.id

    now = _utcnow()
    hunt_input = HuntInput(
        ttps=[technique_id],
        initiated_by="system:validation-feedback",
    )
    row = PatternHuntProposalRow(
        id=generate_id("phpr"),
        org_id=org_id,
        cluster_id=cluster_id,
        score=0.0,
        hunt_input=hunt_input.model_dump(mode="json"),
        rationale=(
            f"Shadow anchor for the #112 detection-tuning suggestion on {technique_id}. "
            "Created by the validation feedback loop only to hold the hunt-pack "
            "suggestion FK; dismissed so the cross-investigation scanner ignores it."
        ),
        state=ProposalState.DISMISSED.value,
        outcome=None,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    await db.flush()
    return row.id


def _tuning_manifest(technique_id: str, verdict: TechniqueVerdict) -> tuple[dict, list[str], str]:
    """Build the (manifest dict, technique_ids, rationale) for a tuning suggestion.

    Captures the offending rule (the earliest fired rule, when present) and the
    observed-vs-expected latency/severity that justify the tuning.
    """
    from btagent_shared.types.huntpack import HuntPackManifest, HuntPackSource, HuntRule

    fired = verdict.fired_rules[0] if verdict.fired_rules else None
    if fired is not None:
        rule_yaml = (
            f"title: {fired.rule_title or fired.rule_id} — tuning candidate\n"
            "status: experimental\n"
            "description: >-\n"
            f"  Rule {fired.rule_id} fired for {technique_id} but scored "
            f"'{verdict.verdict.value}' on validation. Review its severity/latency.\n"
            f"tags:\n  - attack.{technique_id.lower().replace('.', '_')}\n"
            "logsource:\n  category: process_creation\n"
            "detection:\n"
            "  selection:\n"
            "    # TODO(detection-engineering): tune the existing rule; this\n"
            "    # skeleton names the rule that needs adjustment.\n"
            "    CommandLine|contains: PLACEHOLDER\n"
            "  condition: selection\n"
            f"level: {verdict.expected_severity.value}\n"
        )
        rule_id = f"tune-{fired.rule_id}"[:64]
        rule_title = f"Tune {fired.rule_title or fired.rule_id} ({technique_id})"[:300]
    else:
        rule_yaml = _gap_sigma_skeleton(technique_id, "Rule fired but scored off-target.")
        rule_id = f"tune-{technique_id}"[:64]
        rule_title = f"Tune detection for {technique_id}"[:300]

    manifest = HuntPackManifest(
        id=f"pack-tuning-{technique_id}"[:200],
        version="1",
        source=HuntPackSource.AI_AUTHORED,
        description=(
            f"Detection tuning suggested from a validation run: {technique_id} scored "
            f"'{verdict.verdict.value}'. Promote after tuning the offending rule."
        ),
        mitre_techniques=[technique_id],
        enabled_by_default=False,
        rules=[
            HuntRule(
                id=rule_id,
                title=rule_title,
                sigma_yaml=rule_yaml,
                mitre_techniques=[technique_id],
                severity=verdict.expected_severity,
            )
        ],
    )

    observed_sev = verdict.observed_severity.value if verdict.observed_severity else "unknown"
    latency = (
        f"{verdict.latency_seconds:.0f}s vs SLA {verdict.latency_sla_seconds:.0f}s"
        if verdict.latency_seconds is not None
        else "n/a"
    )
    rationale = (
        f"Validation scored {technique_id} as '{verdict.verdict.value}': the rule fired "
        f"but off-target. Observed severity {observed_sev} vs expected "
        f"{verdict.expected_severity.value}; latency {latency}. File as a #112 hunt-pack "
        "tuning suggestion so an analyst adjusts the detection's severity/latency."
    )
    return manifest.model_dump(mode="json"), [technique_id], rationale


async def file_tuning_suggestion(
    db: AsyncSession,
    *,
    org_id: str,
    verdict: TechniqueVerdict,
    plan_id: str | None = None,
):
    """File (or refresh) a #112 hunt-pack tuning suggestion for a late/wrong-severity verdict.

    Reuses the #120 :class:`HuntPackSuggestionRow` review queue (migration-free;
    see the module docstring for the shadow-parent detail). Idempotent per
    ``(org, technique)``: a re-scored technique refreshes the still-``suggested``
    draft in place (bumping ``hit_count`` as a reinforcement counter) and never
    overwrites an analyst decision. Returns the suggestion row. Flushes, never
    commits.
    """
    from btagent_backend.db.models_pattern import HuntPackSuggestionRow

    technique_id = verdict.technique_id
    proposal_id = await _ensure_tuning_shadow_proposal(db, org_id=org_id, technique_id=technique_id)
    manifest, technique_ids, rationale = _tuning_manifest(technique_id, verdict)
    title = f"Detection tuning: {technique_id} ({verdict.verdict.value})"[:300]
    now = _utcnow()

    existing = (
        await db.execute(
            select(HuntPackSuggestionRow).where(
                HuntPackSuggestionRow.org_id == org_id,
                HuntPackSuggestionRow.proposal_id == proposal_id,
            )
        )
    ).scalar_one_or_none()
    if existing is None:
        row = HuntPackSuggestionRow(
            id=generate_id("hpsug"),
            org_id=org_id,
            proposal_id=proposal_id,
            plan_id=plan_id or f"{TUNING_CLUSTER_PREFIX}:{technique_id}",
            title=title,
            technique_ids=technique_ids,
            manifest=manifest,
            rationale=rationale,
            state="suggested",
            hit_count=1,
            created_at=now,
            updated_at=now,
        )
        db.add(row)
        await db.flush()
        logger.info(
            "tuning #112 suggestion filed for %s (org=%s, verdict=%s)",
            technique_id,
            org_id,
            verdict.verdict.value,
        )
        return row

    # Refresh the draft only while still awaiting review; an accepted / dismissed
    # row keeps the analyst decision. hit_count always advances so the inbox can
    # surface repeatedly-flagged detections.
    if existing.state == "suggested":
        existing.plan_id = plan_id or existing.plan_id
        existing.title = title
        existing.technique_ids = technique_ids
        existing.manifest = manifest
        existing.rationale = rationale
    existing.hit_count += 1
    existing.updated_at = now
    await db.flush()
    logger.info(
        "tuning #112 suggestion refreshed for %s (org=%s, verdict=%s, hit_count=%d)",
        technique_id,
        org_id,
        verdict.verdict.value,
        existing.hit_count,
    )
    return existing


# --------------------------------------------------------------------------- #
# Dispatcher — called from the validation completion path
# --------------------------------------------------------------------------- #


async def dispatch_validation_feedback(
    db: AsyncSession,
    *,
    org_id: str,
    report: ValidationReport,
) -> dict[str, int]:
    """Route every scored verdict in ``report`` to its feedback loop, best-effort.

    ``silent_gap`` → (A) #113 proposal; ``late`` / ``wrong_severity`` → (B) #112
    tuning suggestion. Each verdict is dispatched independently and wrapped so a
    single feedback failure can never sink the persisted run (already flushed by
    the caller) nor block the other verdicts. Pure in-process replay reports
    carry no ``verdicts`` and are a no-op.

    Returns a small counter dict (``silent_gap`` / ``tuning`` filed) for logging
    and tests.
    """
    filed = {"silent_gap": 0, "tuning": 0}
    for verdict in report.verdicts:
        try:
            if verdict.verdict == ValidationVerdict.SILENT_GAP:
                await file_silent_gap_proposal(
                    db,
                    org_id=org_id,
                    technique_id=verdict.technique_id,
                    detail=verdict.detail,
                )
                filed["silent_gap"] += 1
            elif verdict.verdict in _TUNING_VERDICTS:
                await file_tuning_suggestion(
                    db, org_id=org_id, verdict=verdict, plan_id=report.run_id
                )
                filed["tuning"] += 1
        except Exception:  # noqa: BLE001 — feedback must never sink the run write
            logger.warning(
                "validation feedback loop failed for technique %s (verdict=%s, org=%s)",
                verdict.technique_id,
                verdict.verdict.value,
                org_id,
                exc_info=True,
            )
    if filed["silent_gap"] or filed["tuning"]:
        logger.info(
            "validation feedback dispatched (org=%s): %d silent-gap proposal(s), "
            "%d tuning suggestion(s)",
            org_id,
            filed["silent_gap"],
            filed["tuning"],
        )
    return filed


__all__ = [
    "dispatch_validation_feedback",
    "file_silent_gap_proposal",
    "file_tuning_suggestion",
]
