"""Detection-coverage map derived from validation-run history (#118 Phase C).

Answers the acceptance question "which ATT&CK techniques are stale — validated
> N days ago, or never validated?" **without a schema change**: ``last_validated``
is derived per technique as the max ``generated_at`` over the EXISTING
``detection_validation_runs`` rows that actually exercised the technique. There
is no new column and no migration.

What counts as "validated at" a run
-----------------------------------
A run exercised a technique (and thus stamps its ``last_validated``) when:

* the run carries a per-technique ``verdict`` for it that is **not** ``errored``
  (an errored emulation could not be scored, so it does not count — matching
  ``CoverageDelta.last_validated``: "last produced a non-errored verdict"), OR
* the run is a pure in-process replay (no verdicts) and the technique appears in
  its ``coverage_by_technique`` roll-up (the replay exercised it).

The technique universe
----------------------
The map is drawn over the union of the org's **techniques that have a detection
proposal** (``detection_proposals.technique_ids``) and every technique any of
its validation runs exercised — i.e. the techniques the org actually cares
about. Each technique with a detection proposal but no (recent) validation is
exactly the "never / stale" signal the map surfaces. Technique display names are
annotated from the seeded MITRE set when present.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_cti import DetectionProposalRow
from btagent_backend.db.models_mitre import MitreTechniqueRow
from btagent_backend.db.models_validation import DetectionValidationRunRow

logger = logging.getLogger("btagent.services.validation_coverage")

# Default staleness horizon: a technique validated longer ago than this (or
# never) is flagged stale.
DEFAULT_STALE_DAYS = 90


@dataclass(frozen=True)
class CoverageMapEntry:
    """One technique's coverage/staleness row in the map."""

    technique_id: str
    name: str | None
    last_validated: datetime | None
    last_verdict: str | None
    days_since_validated: int | None
    stale: bool
    has_detection: bool


def _to_aware(dt: datetime) -> datetime:
    """Normalise a possibly-naive persisted timestamp to UTC-aware."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _validated_techniques_in_run(
    row: DetectionValidationRunRow,
) -> dict[str, str | None]:
    """Techniques a single run exercised → the verdict label (None for replay).

    Errored-only emulation verdicts are excluded (the technique was not scored).
    """
    verdicts = list(row.verdicts or [])
    if verdicts:
        out: dict[str, str | None] = {}
        for v in verdicts:
            tech = v.get("technique_id")
            verdict = v.get("verdict")
            if not tech or verdict == "errored":
                continue
            out[tech] = verdict
        return out
    # Pure replay run — no verdicts; every covered technique was exercised.
    return {
        c.get("technique_id"): None
        for c in (row.coverage_by_technique or [])
        if c.get("technique_id")
    }


async def build_coverage_map(
    db: AsyncSession,
    *,
    org_id: str,
    stale_days: int = DEFAULT_STALE_DAYS,
    only_stale: bool = False,
    now: datetime | None = None,
) -> list[CoverageMapEntry]:
    """Build the per-technique coverage/staleness map for one org.

    Parameters
    ----------
    stale_days:
        A technique validated more than this many days ago (or never) is stale.
    only_stale:
        When True, return only the stale techniques (the ">90d untested /
        never-validated" filter).
    now:
        Injectable clock for deterministic tests; defaults to ``datetime.now``.

    Returns entries sorted stale-first, then oldest-validation first, then by
    technique id — the order an analyst triaging coverage gaps wants.
    """
    now = now or datetime.now(UTC)

    # ---- last_validated (+ verdict) per technique, max over the run history.
    run_rows = (
        (
            await db.execute(
                select(DetectionValidationRunRow).where(DetectionValidationRunRow.org_id == org_id)
            )
        )
        .scalars()
        .all()
    )
    last_validated: dict[str, datetime] = {}
    last_verdict: dict[str, str | None] = {}
    for row in run_rows:
        gen_at = _to_aware(row.generated_at)
        for tech, verdict in _validated_techniques_in_run(row).items():
            prev = last_validated.get(tech)
            if prev is None or gen_at > prev:
                last_validated[tech] = gen_at
                last_verdict[tech] = verdict

    # ---- techniques the org has a detection proposal for.
    proposal_tech_lists = (
        (
            await db.execute(
                select(DetectionProposalRow.technique_ids).where(
                    DetectionProposalRow.org_id == org_id
                )
            )
        )
        .scalars()
        .all()
    )
    techniques_with_detection: set[str] = set()
    for tech_list in proposal_tech_lists:
        techniques_with_detection.update(tech_list or [])

    # ---- universe = has-detection ∪ ever-validated.
    universe = techniques_with_detection | set(last_validated)
    if not universe:
        return []

    # ---- MITRE display names for the universe (single query; best-effort).
    names: dict[str, str] = {}
    name_rows = (
        await db.execute(
            select(MitreTechniqueRow.id, MitreTechniqueRow.name).where(
                MitreTechniqueRow.id.in_(universe)
            )
        )
    ).all()
    for tech_id, name in name_rows:
        names[tech_id] = name

    entries: list[CoverageMapEntry] = []
    for tech in universe:
        validated_at = last_validated.get(tech)
        if validated_at is None:
            days_since: int | None = None
            stale = True
        else:
            days_since = (now - validated_at).days
            stale = days_since > stale_days
        entry = CoverageMapEntry(
            technique_id=tech,
            name=names.get(tech),
            last_validated=validated_at,
            last_verdict=last_verdict.get(tech),
            days_since_validated=days_since,
            stale=stale,
            has_detection=tech in techniques_with_detection,
        )
        if only_stale and not entry.stale:
            continue
        entries.append(entry)

    # Stale first; within that, oldest-validation (None sorts oldest) first;
    # then technique id for a stable order.
    def _sort_key(e: CoverageMapEntry) -> tuple[int, float, str]:
        never = e.last_validated is None
        ts = 0.0 if never else e.last_validated.timestamp()
        return (0 if e.stale else 1, ts, e.technique_id)

    entries.sort(key=_sort_key)
    logger.info(
        "coverage map built (org=%s): %d technique(s), %d stale (>%dd/never)",
        org_id,
        len(entries),
        sum(1 for e in entries if e.stale),
        stale_days,
    )
    return entries


__all__ = ["CoverageMapEntry", "DEFAULT_STALE_DAYS", "build_coverage_map"]
