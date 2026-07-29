"""Draft → analyst-final rule-edit export with edit distance (#113).

A **read-only** export of ``(draft rule, analyst-edited final rule)`` pairs from
the rows the CTI → Detection pipeline already stores — the drafter's generated
``detection_proposals.sigma_yaml`` and the analyst's ``final_sigma_yaml`` (the
Phase-C draft-edit path). No new table, no new column, no migration: the pairs
are derived at read time.

Why this exists
---------------
It is the quality signal for the rule drafter. Every pair is a preference
record in the DPO sense — the analyst-edited body is the *chosen* completion and
the model's draft is the *rejected* one — and the edit distance between them is
a scalar "how far off was the draft?" metric. Aggregated (mean normalised
distance, share of drafts shipped unedited) it answers "is the drafter getting
better?" without any human labelling round.

What it is NOT
--------------
It does not train anything and it does not leave the process: it returns data to
an authorised, org-scoped caller. Rule bodies are internal detection content, so
the route gates on ``hunt:view`` and every query is org-scoped — there is no
cross-tenant pair in an export.

Metrics
-------
* ``char_distance`` — Levenshtein edit distance between draft and final.
* ``normalized_distance`` — ``char_distance / max(len(draft), len(final))``,
  in ``[0, 1]``; ``similarity`` is ``1 - normalized_distance``.
* line-level ``lines_added`` / ``lines_removed`` / ``lines_changed`` from
  :class:`difflib.SequenceMatcher`, which is what a reviewer actually sees.
"""

from __future__ import annotations

import difflib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_cti import DetectionProposalRow

logger = logging.getLogger("btagent.services.detection_edit_export")

# Levenshtein is O(n*m); Sigma rules are small, but a pathological body must not
# be able to burn CPU on a read endpoint. Longer inputs are compared on their
# leading ``_MAX_DISTANCE_CHARS`` characters and flagged ``truncated``.
MAX_DISTANCE_CHARS = 20_000

# Default cap on exported pairs (an analysis pull, not a bulk dump).
DEFAULT_EXPORT_LIMIT = 200
MAX_EXPORT_LIMIT = 1000


def levenshtein(a: str, b: str) -> int:
    """Classic Levenshtein edit distance (two-row DP, O(min(n,m)) memory)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    # Keep the inner loop over the shorter string.
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(
                min(
                    previous[j] + 1,  # deletion
                    current[j - 1] + 1,  # insertion
                    previous[j - 1] + (ca != cb),  # substitution
                )
            )
        previous = current
    return previous[-1]


@dataclass(frozen=True)
class EditDistanceMetrics:
    """How far the analyst's final rule sits from the drafted rule."""

    char_distance: int
    normalized_distance: float
    similarity: float
    draft_chars: int
    final_chars: int
    lines_added: int
    lines_removed: int
    lines_changed: int
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "char_distance": self.char_distance,
            "normalized_distance": self.normalized_distance,
            "similarity": self.similarity,
            "draft_chars": self.draft_chars,
            "final_chars": self.final_chars,
            "lines_added": self.lines_added,
            "lines_removed": self.lines_removed,
            "lines_changed": self.lines_changed,
            "truncated": self.truncated,
        }


def compute_edit_metrics(draft: str, final: str) -> EditDistanceMetrics:
    """Character- and line-level edit metrics between a draft and its final."""
    draft = draft or ""
    final = final or ""
    truncated = max(len(draft), len(final)) > MAX_DISTANCE_CHARS
    a = draft[:MAX_DISTANCE_CHARS]
    b = final[:MAX_DISTANCE_CHARS]

    distance = levenshtein(a, b)
    span = max(len(a), len(b))
    normalized = round(distance / span, 6) if span else 0.0

    added = removed = changed = 0
    matcher = difflib.SequenceMatcher(a=draft.splitlines(), b=final.splitlines(), autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "insert":
            added += j2 - j1
        elif tag == "delete":
            removed += i2 - i1
        elif tag == "replace":
            changed += max(i2 - i1, j2 - j1)

    return EditDistanceMetrics(
        char_distance=distance,
        normalized_distance=normalized,
        similarity=round(1.0 - normalized, 6),
        draft_chars=len(draft),
        final_chars=len(final),
        lines_added=added,
        lines_removed=removed,
        lines_changed=changed,
        truncated=truncated,
    )


@dataclass(frozen=True)
class EditPair:
    """One (draft → analyst-final) preference record with its edit metrics."""

    proposal_row_id: str
    proposal_id: str
    org_id: str
    title: str
    technique_ids: list[str]
    source_stix_id: str
    bundle_id: str | None
    state: str
    pr_outcome: str
    edited: bool
    draft_sigma_yaml: str
    final_sigma_yaml: str
    metrics: EditDistanceMetrics
    review_rationale: str
    reviewed_by: str | None
    reviewed_at: datetime | None
    created_at: datetime
    updated_at: datetime

    def to_dict(self) -> dict[str, Any]:
        """Serialise, including the DPO-style ``chosen`` / ``rejected`` framing."""
        return {
            "proposal_row_id": self.proposal_row_id,
            "proposal_id": self.proposal_id,
            "org_id": self.org_id,
            "title": self.title,
            "technique_ids": list(self.technique_ids),
            "source_stix_id": self.source_stix_id,
            "bundle_id": self.bundle_id,
            "state": self.state,
            "pr_outcome": self.pr_outcome,
            "edited": self.edited,
            # Preference framing: the analyst's body is the chosen completion,
            # the drafter's body the rejected one.
            "chosen": self.final_sigma_yaml,
            "rejected": self.draft_sigma_yaml,
            "draft_sigma_yaml": self.draft_sigma_yaml,
            "final_sigma_yaml": self.final_sigma_yaml,
            "metrics": self.metrics.to_dict(),
            "review_rationale": self.review_rationale,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True)
class EditPairSummary:
    """Aggregate drafter-quality signal over the exported pairs."""

    total_pairs: int
    edited_pairs: int
    unedited_pairs: int
    edited_fraction: float
    mean_normalized_distance: float
    median_normalized_distance: float
    max_normalized_distance: float
    mean_char_distance: float
    techniques_covered: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_pairs": self.total_pairs,
            "edited_pairs": self.edited_pairs,
            "unedited_pairs": self.unedited_pairs,
            "edited_fraction": self.edited_fraction,
            "mean_normalized_distance": self.mean_normalized_distance,
            "median_normalized_distance": self.median_normalized_distance,
            "max_normalized_distance": self.max_normalized_distance,
            "mean_char_distance": self.mean_char_distance,
            "techniques_covered": list(self.techniques_covered),
        }


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2


def _pair_from_row(row: DetectionProposalRow) -> EditPair:
    draft = row.sigma_yaml or ""
    edited = bool(row.final_sigma_yaml) and (row.final_sigma_yaml or "").strip() != draft.strip()
    final = row.final_sigma_yaml if row.final_sigma_yaml else draft
    return EditPair(
        proposal_row_id=row.id,
        proposal_id=row.proposal_id,
        org_id=row.org_id,
        title=row.title,
        technique_ids=list(row.technique_ids or []),
        source_stix_id=row.source_stix_id,
        bundle_id=row.bundle_id,
        state=row.state,
        pr_outcome=row.pr_outcome,
        edited=edited,
        draft_sigma_yaml=draft,
        final_sigma_yaml=final,
        metrics=compute_edit_metrics(draft, final),
        review_rationale=row.review_rationale or "",
        reviewed_by=row.reviewed_by,
        reviewed_at=row.reviewed_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def summarize_pairs(pairs: list[EditPair]) -> EditPairSummary:
    """Roll a list of pairs up into the drafter-quality summary."""
    normalized = [p.metrics.normalized_distance for p in pairs]
    edited = [p for p in pairs if p.edited]
    techniques: set[str] = set()
    for pair in pairs:
        techniques.update(pair.technique_ids)
    total = len(pairs)
    return EditPairSummary(
        total_pairs=total,
        edited_pairs=len(edited),
        unedited_pairs=total - len(edited),
        edited_fraction=round(len(edited) / total, 6) if total else 0.0,
        mean_normalized_distance=round(sum(normalized) / total, 6) if total else 0.0,
        median_normalized_distance=round(_median(normalized), 6),
        max_normalized_distance=round(max(normalized), 6) if normalized else 0.0,
        mean_char_distance=(
            round(sum(p.metrics.char_distance for p in pairs) / total, 3) if total else 0.0
        ),
        techniques_covered=sorted(techniques),
    )


async def export_edit_pairs(
    db: AsyncSession,
    *,
    org_id: str,
    include_unedited: bool = False,
    only_shipped: bool = False,
    limit: int = DEFAULT_EXPORT_LIMIT,
) -> tuple[list[EditPair], EditPairSummary]:
    """Export ``(draft → analyst-final)`` pairs for one org, newest first.

    Read-only: no row is written or mutated. Strictly org-scoped — the query
    filters on ``org_id`` so an export can never contain another tenant's rules.

    Parameters
    ----------
    include_unedited:
        Also emit rows the analyst shipped unchanged (final == draft, distance
        0). They are the "draft was good enough" positives; off by default so
        the export is the pure edit signal.
    only_shipped:
        Restrict to rules that actually reached a detection-repo PR
        (``pr_url`` set) — the highest-confidence preference records.
    limit:
        Cap on returned pairs (clamped to :data:`MAX_EXPORT_LIMIT`).
    """
    limit = max(1, min(int(limit), MAX_EXPORT_LIMIT))

    where = [DetectionProposalRow.org_id == org_id]
    if not include_unedited:
        # An edit exists only on the Phase-C draft-edit path, which also flips
        # the row to ``modified``; both conditions keep the query honest.
        where.append(DetectionProposalRow.final_sigma_yaml.isnot(None))
    if only_shipped:
        where.append(DetectionProposalRow.pr_url.isnot(None))

    rows = (
        (
            await db.execute(
                select(DetectionProposalRow)
                .where(*where)
                .order_by(DetectionProposalRow.updated_at.desc(), DetectionProposalRow.id)
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )

    pairs = [_pair_from_row(row) for row in rows]
    if not include_unedited:
        # A stored final identical to the draft is not an edit signal.
        pairs = [p for p in pairs if p.edited]
    summary = summarize_pairs(pairs)
    logger.info(
        "detection edit-pair export: org=%s pairs=%d edited=%d mean_norm_distance=%.4f",
        org_id,
        summary.total_pairs,
        summary.edited_pairs,
        summary.mean_normalized_distance,
    )
    return pairs, summary


__all__ = [
    "DEFAULT_EXPORT_LIMIT",
    "MAX_EXPORT_LIMIT",
    "EditDistanceMetrics",
    "EditPair",
    "EditPairSummary",
    "compute_edit_metrics",
    "export_edit_pairs",
    "levenshtein",
    "summarize_pairs",
]
