"""CTI → Detection service (issue #113 slice).

Thin shell that validates a STIX bundle and delegates to the pure-logic
core in :mod:`btagent_shared.hunt.cti_to_detection`.

This service layer exists so the API route (and any future background
task or event consumer) share a single call site, and so the pure-logic
core can stay in ``shared/`` without importing FastAPI or DB models.

Scope for this slice
--------------------
- Accepts a raw STIX bundle dict (the ``stix_bundle_id`` resolution path
  is left as a TODO for the follow-up PR that adds proposal persistence
  and bundle-by-id lookup).
- Applies TLP gating via the shared gate (TLP:RED bundles raise
  :class:`btagent_shared.security.TLPViolation`).
- Returns :class:`CTIToDetectionResponse` — proposals are *not* persisted
  in this slice.

Telemetry hook
--------------
The ``# TELEMETRY_HOOK`` comment below marks the insertion point for
validation telemetry once issue #118 (rule-quality telemetry) lands.
Replace the pass statement with your telemetry emit call.
"""

from __future__ import annotations

import logging
from typing import Any

from btagent_shared.hunt.cti_to_detection import process_stix_bundle
from btagent_shared.security.tlp import TLPViolation
from btagent_shared.types.config import TLP
from btagent_shared.types.detection_proposal import CTIToDetectionResponse

logger = logging.getLogger("btagent.services.cti_detection")


class CTIDetectionService:
    """Produce Sigma rule proposals from a STIX 2.1 bundle.

    Usage::

        svc = CTIDetectionService()
        response = svc.propose_from_bundle(bundle=my_bundle, active_tlp=TLP.GREEN)
        for proposal in response.proposals:
            print(proposal.sigma_yaml)
    """

    def propose_from_bundle(
        self,
        *,
        bundle: dict[str, Any],
        active_tlp: TLP = TLP.GREEN,
    ) -> CTIToDetectionResponse:
        """Convert a raw STIX 2.1 bundle into Sigma rule proposals.

        Parameters
        ----------
        bundle:
            Raw STIX 2.1 bundle dict (``{"type": "bundle", "objects": [...]}``)
        active_tlp:
            TLP classification for this operation.  TLP:RED is refused.

        Returns
        -------
        CTIToDetectionResponse
            Proposals + skipped records.

        Raises
        ------
        TLPViolation
            If ``active_tlp`` is :attr:`TLP.RED` or the bundle contains any
            TLP:RED-marked objects.
        ValueError
            If ``bundle`` is not a dict or is missing the ``"type"`` key.
        """
        if not isinstance(bundle, dict):
            raise ValueError("stix_bundle must be a dict")
        if bundle.get("type") != "bundle":
            raise ValueError(
                f"Expected a STIX bundle (type='bundle'), got type={bundle.get('type')!r}"
            )

        logger.info(
            "CTI detection pipeline: processing bundle %s with TLP=%s (%d objects)",
            bundle.get("id", "<no-id>"),
            active_tlp,
            len(bundle.get("objects", [])),
        )

        response = process_stix_bundle(bundle, active_tlp=active_tlp)

        # TELEMETRY_HOOK: emit proposal telemetry for #118 here.
        # e.g. emit_cti_detection_telemetry(response, bundle_id=bundle.get("id"))
        # (no-op until #118 lands)

        logger.info(
            "CTI detection pipeline complete: %d proposals, %d skipped",
            len(response.proposals),
            len(response.skipped),
        )
        return response

    def propose_from_bundle_id(
        self,
        *,
        bundle_id: str,
        active_tlp: TLP = TLP.GREEN,
    ) -> CTIToDetectionResponse:
        """Resolve a previously-imported bundle by ID and produce proposals.

        NOT IMPLEMENTED in this slice.  The bundle-by-id resolution path
        requires proposal persistence (deferred to the follow-up PR).

        Raises
        ------
        NotImplementedError
            Always — this path is a stub for the next slice.
        """
        raise NotImplementedError(
            f"Bundle-by-id resolution (bundle_id={bundle_id!r}) is deferred to the "
            "proposal-persistence follow-up PR.  Pass the raw bundle dict via "
            "propose_from_bundle() instead."
        )


__all__ = ["CTIDetectionService"]


# ---------------------------------------------------------------------------
# Persistence + review lifecycle (#113 back half, slice 1)
#
# Module-level async helpers following the codebase convention: AsyncSession
# first, flush-not-commit (the route / job owns the single commit).
# ---------------------------------------------------------------------------

from datetime import UTC, datetime  # noqa: E402

from btagent_shared.types.detection_proposal import (  # noqa: E402
    DetectionProposal,
    ProposalState,
)
from btagent_shared.utils.ids import generate_id  # noqa: E402
from sqlalchemy import func, select  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

from btagent_backend.db.models_cti import DetectionProposalRow  # noqa: E402

# States an analyst has explicitly decided — a re-propose never clobbers them.
_DECIDED_STATES = frozenset(
    {ProposalState.ACCEPTED.value, ProposalState.REJECTED.value, ProposalState.MODIFIED.value}
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


async def persist_proposals(
    db: AsyncSession,
    *,
    org_id: str,
    proposals: list[DetectionProposal],
    bundle_id: str | None = None,
) -> tuple[int, int, int]:
    """Upsert pipeline proposals into ``detection_proposals``.

    Keyed on ``(org_id, source_stix_id)``:

    * no existing row → insert (``created``)
    * existing row still ``proposed`` → refresh content (``updated``) — the
      pipeline's newest view of the indicator wins while nobody has reviewed
    * existing row already decided → leave untouched (``unchanged``) — an
      analyst decision is never silently overwritten by a re-import

    Returns ``(created, updated, unchanged)`` counts. Flushes, never commits.
    """
    if not proposals:
        return (0, 0, 0)

    stix_ids = [p.source_stix_id for p in proposals]
    existing_rows = (
        (
            await db.execute(
                select(DetectionProposalRow).where(
                    DetectionProposalRow.org_id == org_id,
                    DetectionProposalRow.source_stix_id.in_(stix_ids),
                )
            )
        )
        .scalars()
        .all()
    )
    by_stix_id = {row.source_stix_id: row for row in existing_rows}

    created = updated = unchanged = 0
    now = _utcnow()
    for proposal in proposals:
        row = by_stix_id.get(proposal.source_stix_id)
        if row is None:
            db.add(
                DetectionProposalRow(
                    id=generate_id("dprop"),
                    org_id=org_id,
                    proposal_id=proposal.id,
                    source_stix_id=proposal.source_stix_id,
                    bundle_id=bundle_id,
                    title=proposal.title,
                    sigma_yaml=proposal.sigma_yaml,
                    technique_ids=list(proposal.technique_ids),
                    confidence=proposal.confidence,
                    rationale=proposal.rationale,
                    state=ProposalState.PROPOSED.value,
                    created_at=now,
                    updated_at=now,
                )
            )
            created += 1
        elif row.state in _DECIDED_STATES:
            unchanged += 1
        else:
            row.proposal_id = proposal.id
            row.title = proposal.title
            row.sigma_yaml = proposal.sigma_yaml
            row.technique_ids = list(proposal.technique_ids)
            row.confidence = proposal.confidence
            row.rationale = proposal.rationale
            row.bundle_id = bundle_id or row.bundle_id
            row.updated_at = now
            updated += 1

    await db.flush()
    logger.info(
        "detection proposals persisted: created=%d updated=%d unchanged=%d (org=%s bundle=%s)",
        created,
        updated,
        unchanged,
        org_id,
        bundle_id or "<none>",
    )
    return (created, updated, unchanged)


async def list_proposals(
    db: AsyncSession,
    *,
    org_id: str,
    state: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[DetectionProposalRow], int]:
    """Org-scoped, paginated proposal listing, newest-updated first."""
    where = [DetectionProposalRow.org_id == org_id]
    if state:
        where.append(DetectionProposalRow.state == state)

    total = (
        await db.execute(select(func.count()).select_from(DetectionProposalRow).where(*where))
    ).scalar_one()
    rows = (
        (
            await db.execute(
                select(DetectionProposalRow)
                .where(*where)
                .order_by(DetectionProposalRow.updated_at.desc(), DetectionProposalRow.id)
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        .scalars()
        .all()
    )
    return list(rows), int(total)


async def set_proposal_state(
    db: AsyncSession,
    *,
    org_id: str,
    row_id: str,
    state: ProposalState,
    review_rationale: str = "",
    reviewed_by: str | None = None,
) -> DetectionProposalRow:
    """Record an analyst decision on a proposal.

    Only ``proposed`` rows may be decided — re-deciding raises
    :class:`ValueError` with a message the route surfaces as 409. A missing /
    cross-org row raises :class:`LookupError` (route surfaces 404, masking
    tenancy).
    """
    row = (
        await db.execute(
            select(DetectionProposalRow).where(
                DetectionProposalRow.id == row_id,
                DetectionProposalRow.org_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise LookupError(f"Detection proposal not found: {row_id}")
    if row.state in _DECIDED_STATES:
        raise ValueError(f"Detection proposal already {row.state}")

    row.state = state.value
    row.review_rationale = review_rationale
    row.reviewed_by = reviewed_by
    row.reviewed_at = _utcnow()
    row.updated_at = row.reviewed_at
    await db.flush()
    return row


async def validate_proposal(
    db: AsyncSession,
    *,
    org_id: str,
    row_id: str,
    backends: list[str] | None = None,
    lookback_hours: int = 24 * 30,
) -> DetectionProposalRow:
    """Validate a proposal's Sigma rule against historical telemetry (#113 slice 2).

    Runs the engine rule validator (transpile per backend + execute through
    the integration nodes, mock-aware) and stores the serialised outcome +
    verdict on the row. Read-only with respect to the review lifecycle —
    validation never changes ``state`` and may run on decided rows too (the
    PR composer wants a fresh verdict at composition time).

    Raises :class:`LookupError` for unknown / cross-org rows (route → 404).
    Never commits.
    """
    row = (
        await db.execute(
            select(DetectionProposalRow).where(
                DetectionProposalRow.id == row_id,
                DetectionProposalRow.org_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise LookupError(f"Detection proposal not found: {row_id}")

    # Lazy engine import — pulls the pySigma / integration-node stack.
    from btagent_engine.hunting.rule_validator import validate_rule
    from btagent_engine.node import NodeContext

    ctx = NodeContext(run_id=generate_id("vrun"), org_id=org_id)
    result = await validate_rule(row.sigma_yaml, backends, ctx, lookback_hours=lookback_hours)

    payload = result.model_dump(mode="json")
    payload["verdict"] = result.verdict
    payload["total_hits"] = result.total_hits
    row.validation = payload
    row.validated_at = result.validated_at
    row.updated_at = result.validated_at
    await db.flush()
    logger.info(
        "detection proposal validated: row=%s verdict=%s hits=%d errors=%d",
        row.id,
        result.verdict,
        result.total_hits,
        result.error_count,
    )
    return row


async def get_proposal(
    db: AsyncSession,
    *,
    org_id: str,
    row_id: str,
) -> DetectionProposalRow | None:
    """Org-scoped single-row fetch (None on miss or cross-org)."""
    return (
        await db.execute(
            select(DetectionProposalRow).where(
                DetectionProposalRow.id == row_id,
                DetectionProposalRow.org_id == org_id,
            )
        )
    ).scalar_one_or_none()


# ---------------------------------------------------------------------------
# Detection-repo PR composer (#113 back half, slice 3)
# ---------------------------------------------------------------------------

import re as _re  # noqa: E402

_SLUG_RE = _re.compile(r"[^a-z0-9]+")


def _rule_slug(title: str) -> str:
    """Filesystem-safe slug for a rule file name."""
    slug = _SLUG_RE.sub("_", title.strip().lower()).strip("_")
    return slug or "rule"


def build_pr_files(rows: list[DetectionProposalRow]) -> list[dict[str, str]]:
    """Map accepted proposal rows to detection-repo file payloads.

    Layout: ``rules/<primary-technique|uncategorized>/<slug>.yml``. Path
    collisions (same title twice) are disambiguated with the row id suffix
    so the Git connector's duplicate-path guard never fires spuriously.
    """
    files: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in rows:
        technique = (row.technique_ids or ["uncategorized"])[0].lower()
        path = f"rules/{technique}/{_rule_slug(row.title)}.yml"
        if path in seen:
            path = f"rules/{technique}/{_rule_slug(row.title)}_{row.id[-6:].lower()}.yml"
        seen.add(path)
        files.append({"path": path, "content": row.sigma_yaml})
    return files


def _pr_body(rows: list[DetectionProposalRow]) -> str:
    """Markdown PR body summarising each rule + its telemetry verdict."""
    lines = [
        "Accepted Sigma rule proposals from the CTI → Detection pipeline (#113).",
        "",
        "| Rule | Techniques | Confidence | Telemetry verdict |",
        "|------|------------|------------|-------------------|",
    ]
    for row in rows:
        verdict = (row.validation or {}).get("verdict", "not validated")
        techniques = ", ".join(row.technique_ids or []) or "—"
        lines.append(f"| {row.title} | {techniques} | {row.confidence:.2f} | {verdict} |")
    lines += [
        "",
        "Every rule in this PR was individually accepted by an analyst "
        "(one-shot review decision) before composition.",
    ]
    return "\n".join(lines)


async def compose_detection_pr(
    db: AsyncSession,
    *,
    org_id: str,
    row_ids: list[str],
    title: str | None = None,
) -> dict[str, Any]:
    """Compose a detection-repo PR from accepted proposals (#113 slice 3).

    HITL discipline: only ``accepted`` rows (a one-shot human decision) are
    eligible, and the route gates on a senior-analyst permission — two human
    gates before anything reaches the repo. Rows that already shipped
    (non-null ``pr_url``) are refused; a rule ships once.

    Raises :class:`LookupError` when any row is missing / cross-org (404) and
    :class:`ValueError` for eligibility violations (409). Never commits.
    """
    if not row_ids:
        raise ValueError("compose_detection_pr needs at least one proposal row id")

    rows = (
        (
            await db.execute(
                select(DetectionProposalRow).where(
                    DetectionProposalRow.id.in_(row_ids),
                    DetectionProposalRow.org_id == org_id,
                )
            )
        )
        .scalars()
        .all()
    )
    found = {r.id for r in rows}
    missing = [rid for rid in row_ids if rid not in found]
    if missing:
        raise LookupError(f"Detection proposal(s) not found: {', '.join(missing)}")

    not_accepted = [r.id for r in rows if r.state != ProposalState.ACCEPTED.value]
    if not_accepted:
        raise ValueError(
            f"Only accepted proposals can ship; not accepted: {', '.join(not_accepted)}"
        )
    shipped = [r.id for r in rows if r.pr_url]
    if shipped:
        raise ValueError(f"Proposal(s) already shipped in a PR: {', '.join(shipped)}")

    ordered = sorted(rows, key=lambda r: r.id)
    files = build_pr_files(ordered)
    now = _utcnow()
    branch = f"detections/cti-{now.strftime('%Y%m%d')}-{len(ordered)}-rules"
    pr_title = title or f"detections: {len(ordered)} CTI-derived Sigma rule(s)"

    # Lazy import — the Git connector lives in the agents package (mock-first;
    # live mode raises NotImplementedError until the rollout PR).
    from btagent_agents.mcp.servers.git_mcp import GitMCPServer

    envelope = await GitMCPServer().git_open_detection_pr(
        branch, pr_title, _pr_body(ordered), files
    )

    pr_url = envelope["pr_url"]
    for row in ordered:
        row.pr_url = pr_url
        row.updated_at = now
    await db.flush()
    logger.info("detection PR composed: %s (%d rules, org=%s)", pr_url, len(ordered), org_id)
    return {
        "pr_url": pr_url,
        "branch": envelope["branch"],
        "commit": envelope["commit"],
        "rule_count": len(ordered),
        "row_ids": [r.id for r in ordered],
        "is_mock": envelope.get("is_mock", False),
    }
