"""CTI → Detection service (issue #113 slice).

Thin shell that validates a STIX bundle and delegates to the pure-logic
core in :mod:`btagent_shared.hunt.cti_to_detection`.

This service layer exists so the API route (and any future background
task or event consumer) share a single call site, and so the pure-logic
core can stay in ``shared/`` without importing FastAPI or DB models.

What this module does
---------------------
- :meth:`CTIDetectionService.propose_from_bundle` takes a raw STIX bundle
  dict, applies TLP gating via the shared gate (TLP:RED bundles raise
  :class:`btagent_shared.security.TLPViolation`), and returns a
  :class:`CTIToDetectionResponse`.
- The module-level async helpers below persist and drive the review
  lifecycle: :func:`persist_proposals`, :func:`list_proposals`,
  :func:`set_proposal_state`, :func:`validate_proposal`.
- :func:`match_data_sources` runs the #113 ``DataSourceMatcher`` over a stored
  rule body so its output (which connectors can feed the rule, which required
  OCSF classes nothing emits) is **persisted** on the row instead of discarded
  (#501). :func:`connected_connector_ids` supplies the org's connector set.

Resolving a bundle by id
------------------------
There is deliberately no ``propose_from_bundle_id`` here. The route owns
that step: ``POST /cti/propose-detections`` loads the stored bundle via
:mod:`btagent_backend.services.stix_bundle_store` (404 on a miss) and then
calls :meth:`propose_from_bundle` with the resolved dict. Keeping the
lookup in the route is what lets this service stay free of a DB session on
the pure-proposal path.

Telemetry hook
--------------
``# TELEMETRY_HOOK`` below marks where proposal telemetry would be emitted.
It is still an intentional no-op: detection *validation* shipped (#118's
replay + ``detection_validation_runs``), but per-proposal rule-quality
telemetry has not been wired.
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

        # TELEMETRY_HOOK: emit per-proposal rule-quality telemetry here.
        # e.g. emit_cti_detection_telemetry(response, bundle_id=bundle.get("id"))
        # Intentionally a no-op: #118's replay/validation shipped, but
        # rule-quality telemetry itself was never wired.

        logger.info(
            "CTI detection pipeline complete: %d proposals, %d skipped",
            len(response.proposals),
            len(response.skipped),
        )
        return response


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
    PROutcome,
)
from btagent_shared.utils.ids import generate_id  # noqa: E402
from sqlalchemy import func, select  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

from btagent_backend.db.models_connector import ConnectorCredentialRow  # noqa: E402
from btagent_backend.db.models_cti import DetectionProposalRow  # noqa: E402

# States an analyst has explicitly decided — a re-propose never clobbers them.
_DECIDED_STATES = frozenset(
    {ProposalState.ACCEPTED.value, ProposalState.REJECTED.value, ProposalState.MODIFIED.value}
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# DataSourceMatcher persistence (#501 — the gap set the Coverage Console reads)
#
# The #113 ``DataSourceMatcher`` already answers "can the org's telemetry even
# feed this rule?". Before migration 0066 that answer was thrown away and the
# console *inferred* a weaker one from the validation blob. These helpers run the
# same matcher against a persisted rule body and hand back exactly the two lists
# the row now stores.
# ---------------------------------------------------------------------------


async def connected_connector_ids(db: AsyncSession, *, org_id: str) -> list[str] | None:
    """Connector ids the org has bound a credential *reference* for, or ``None``.

    ``connector_credentials.connector_name`` matches ``ConnectorManifest.name``
    (the key of ``btagent_agents.mcp.manifests.MANIFESTS``), so an org's bindings
    are precisely its "connected connectors" for reconciliation purposes. Reads
    only the name column — never the ``${secret:...}`` reference — and is
    org-scoped at the query.

    ``None`` (rather than ``[]``) when the org has bound nothing at all: that is
    "we do not know what is wired", and it makes the matcher fall back to its own
    default of treating every manifest as connected. Returning ``[]`` there would
    declare *every* required OCSF class missing for every mock-mode / not-yet-
    onboarded org — a fabricated wall of gaps, which is worse than no signal.
    """
    names = (
        (
            await db.execute(
                select(ConnectorCredentialRow.connector_name).where(
                    ConnectorCredentialRow.org_id == org_id
                )
            )
        )
        .scalars()
        .all()
    )
    cleaned = sorted({(n or "").strip() for n in names} - {""})
    return cleaned or None


def match_data_sources(
    *,
    title: str,
    sigma_yaml: str,
    technique_ids: list[str],
    connected: list[str] | None = None,
) -> tuple[list[str], list[str]] | None:
    """Run the #113 ``DataSourceMatcher`` over a stored rule body.

    Returns ``(data_sources_required, data_source_gaps)`` — connector ids that
    can supply the rule's telemetry, and the OCSF event-class *values* nothing
    connected emits — ready to write to the row.

    Returns ``None`` when no honest reconciliation is possible, and the caller
    must then leave both columns NULL rather than store an empty pair:

    * the connector registry is unavailable (``shared`` may run without the
      ``agents`` package installed) — with no manifests every class would look
      missing;
    * the rule's ``logsource.category`` maps to no OCSF class (Sigma's
      ``generic``, a vendor category) — with nothing required, the reconciliation
      would come back "zero gaps", i.e. it would *invent* coverage.

    Pure and synchronous: no DB, no network, no LLM.
    """
    from btagent_shared.hunt.detection_engineer import (
        DataSourceMatcher,
        connector_ocsf_emits,
        ocsf_classes_for_sigma,
    )
    from btagent_shared.types.detection_engineer import DetectionDraft, DraftMethod

    # Guard 1: probe the UNFILTERED registry. An empty map there means "the
    # manifests are not importable", which is not the same as "nothing is
    # connected" — reconciling against it would call every class missing. A
    # caller that explicitly passes ``connected=[]`` *does* mean "nothing is
    # connected", and that legitimately yields a full gap set.
    if not connector_ocsf_emits():
        logger.debug("data-source match skipped: no connector manifests available")
        return None

    required_classes = ocsf_classes_for_sigma(sigma_yaml)
    # Guard 2: nothing required → nothing to reconcile → no claim either way.
    if not required_classes:
        return None

    draft = DetectionDraft(
        id=generate_id("ddraft"),
        title=title,
        sigma_yaml=sigma_yaml,
        method=DraftMethod.DETERMINISTIC,
        technique_ids=list(technique_ids or []),
        ocsf_classes_required=required_classes,
        generated_at=_utcnow(),
    )
    matched = DataSourceMatcher().match(draft, connected=connected)
    return (
        list(matched.data_sources_required),
        [ocsf_class.value for ocsf_class in matched.data_source_gaps],
    )


def _match_columns(
    *,
    title: str,
    sigma_yaml: str,
    technique_ids: list[str],
    connected: list[str] | None,
) -> dict[str, list[str]]:
    """The matcher output as row column kwargs — ``{}`` when no claim is possible.

    An empty dict leaves both columns untouched (NULL on insert, unchanged on
    update), which is the "matcher never ran" marker the Coverage Console falls
    back on. See :func:`match_data_sources` for when that happens.
    """
    match = match_data_sources(
        title=title,
        sigma_yaml=sigma_yaml,
        technique_ids=technique_ids,
        connected=connected,
    )
    if match is None:
        return {}
    return {"data_sources_required": match[0], "data_source_gaps": match[1]}


async def persist_proposals(
    db: AsyncSession,
    *,
    org_id: str,
    proposals: list[DetectionProposal],
    bundle_id: str | None = None,
    connected: list[str] | None = None,
) -> tuple[int, int, int]:
    """Upsert pipeline proposals into ``detection_proposals``.

    Keyed on ``(org_id, source_stix_id)``:

    * no existing row → insert (``created``)
    * existing row still ``proposed`` → refresh content (``updated``) — the
      pipeline's newest view of the indicator wins while nobody has reviewed
    * existing row already decided → leave untouched (``unchanged``) — an
      analyst decision is never silently overwritten by a re-import

    Every written row also carries the #113 ``DataSourceMatcher`` output
    (``data_sources_required`` / ``data_source_gaps``, #501) so the Coverage
    Console can report the real missing OCSF classes rather than infer coverage
    from the validation blob. ``connected`` overrides the connector set to
    reconcile against; omit it and the org's own credential bindings are used
    (:func:`connected_connector_ids`). A row an analyst has already decided is
    left alone here too — including its stored match — because the whole point of
    ``unchanged`` is that a re-import touches nothing.

    Returns ``(created, updated, unchanged)`` counts. Flushes, never commits.
    """
    if not proposals:
        return (0, 0, 0)

    resolved_connected = (
        connected if connected is not None else await connected_connector_ids(db, org_id=org_id)
    )

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
        if row is not None and row.state in _DECIDED_STATES:
            unchanged += 1
            continue

        # Reconcile this rule's telemetry against the org's connectors once, and
        # use it for both the insert and the refresh path.
        match = _match_columns(
            title=proposal.title,
            sigma_yaml=proposal.sigma_yaml,
            technique_ids=list(proposal.technique_ids),
            connected=resolved_connected,
        )
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
                    **match,
                )
            )
            created += 1
        else:
            row.proposal_id = proposal.id
            row.title = proposal.title
            row.sigma_yaml = proposal.sigma_yaml
            row.technique_ids = list(proposal.technique_ids)
            row.confidence = proposal.confidence
            row.rationale = proposal.rationale
            row.bundle_id = bundle_id or row.bundle_id
            for column, value in match.items():
                setattr(row, column, value)
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


async def get_deployed_technique_ids(db: AsyncSession, *, org_id: str) -> set[str]:
    """Return the ATT&CK techniques an org already covers with a deployed detection.

    "Deployed" == a detection proposal the analyst **accepted** (state
    ``accepted``) or one that already **shipped** to the detection repo
    (``pr_url`` set — a modified-then-composed rule counts too). The result is
    the union of those rows' ``technique_ids``.

    Used to populate :attr:`ExecSummary.coverage_delta` on a compiled HuntPlan
    (#99 Bet-1 cross-reference), so the plan flags which of its hunted
    techniques are already alerting via a rule vs. genuinely dark. Filtering is
    Python-side (no JSONB operators) so it runs identically on Postgres and the
    SQLite test backend.
    """
    rows = (
        await db.execute(
            select(
                DetectionProposalRow.technique_ids,
                DetectionProposalRow.state,
                DetectionProposalRow.pr_url,
            ).where(DetectionProposalRow.org_id == org_id)
        )
    ).all()
    deployed: set[str] = set()
    for technique_ids, state, pr_url in rows:
        if state == ProposalState.ACCEPTED.value or pr_url:
            deployed.update(technique_ids or [])
    return deployed


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


# States from which a proposal may still be edited by the Engineer UI. A
# rejected row is a closed decision; a row that already shipped (``pr_url``) is
# immutable — you cannot rewrite a rule that is already in a PR.
_EDITABLE_STATES = frozenset(
    {ProposalState.PROPOSED.value, ProposalState.ACCEPTED.value, ProposalState.MODIFIED.value}
)


async def set_proposal_sigma(
    db: AsyncSession,
    *,
    org_id: str,
    row_id: str,
    sigma_yaml: str,
    edited_by: str | None = None,
    review_rationale: str = "",
) -> DetectionProposalRow:
    """Record an analyst edit of a proposal's Sigma rule (#113 Phase C draft-edit).

    The "selected and edited via the Engineer UI" acceptance path: the edited
    body must parse as a Sigma rule (a YAML mapping carrying at least ``title``
    and ``detection`` — the minimum a downstream transpiler needs) or a
    :class:`ValueError` is raised (route → 422). On success the cleaned body
    lands on :attr:`DetectionProposalRow.final_sigma_yaml`, the row flips to
    ``modified``, and the composer will ship the edited body (cited as *edited
    from draft*) instead of the generated draft.

    Editing is refused (``ValueError`` → 409) for a rejected row or one that has
    already shipped (``pr_url`` set) — a rule in a PR is immutable. A missing /
    cross-org row raises :class:`LookupError` (route → 404, masking tenancy).
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
    if row.pr_url:
        raise ValueError("Detection proposal already shipped in a PR; its rule is immutable")
    if row.state not in _EDITABLE_STATES:
        raise ValueError(f"Detection proposal in state {row.state!r} cannot be edited")

    # Lazy import — the drafter lives in shared/ and pulls only pydantic/yaml.
    from btagent_shared.hunt.detection_engineer import RuleDrafter

    cleaned = RuleDrafter.parse_drafted_yaml(sigma_yaml)
    if cleaned is None:
        raise ValueError(
            "Edited Sigma does not parse as a rule (need a YAML mapping with "
            "'title' and 'detection' keys)"
        )

    row.final_sigma_yaml = cleaned
    # An edit can move the rule's logsource, so the stored DataSourceMatcher
    # result must follow the body that will actually ship (#501). A body we
    # cannot reconcile leaves the columns as they were rather than blanking a
    # previously valid match.
    for column, value in _match_columns(
        title=row.title,
        sigma_yaml=cleaned,
        technique_ids=list(row.technique_ids or []),
        connected=await connected_connector_ids(db, org_id=org_id),
    ).items():
        setattr(row, column, value)
    row.state = ProposalState.MODIFIED.value
    row.review_rationale = review_rationale
    row.reviewed_by = edited_by
    row.reviewed_at = _utcnow()
    row.updated_at = row.reviewed_at
    await db.flush()
    logger.info(
        "detection proposal edited: row=%s org=%s by=%s (state->modified)",
        row.id,
        org_id,
        edited_by or "<none>",
    )
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

from btagent_shared.hunt.detection_engineer import draft_evidence_sha256  # noqa: E402

_SLUG_RE = _re.compile(r"[^a-z0-9]+")


def _rule_slug(title: str) -> str:
    """Filesystem-safe slug for a rule file name."""
    slug = _SLUG_RE.sub("_", title.strip().lower()).strip("_")
    return slug or "rule"


def _shipped_yaml(row: DetectionProposalRow, final_yaml_by_row: dict[str, str] | None) -> str:
    """The YAML that actually ships for ``row``.

    Precedence: an explicit in-memory override (``final_yaml_by_row``, e.g. a
    request-time edit), then the persisted analyst edit (``final_sigma_yaml``,
    the #113 Phase-C draft-edit path), then the generated draft (``sigma_yaml``)."""
    if final_yaml_by_row and row.id in final_yaml_by_row:
        return final_yaml_by_row[row.id]
    if row.final_sigma_yaml:
        return row.final_sigma_yaml
    return row.sigma_yaml


def build_pr_files(
    rows: list[DetectionProposalRow],
    *,
    final_yaml_by_row: dict[str, str] | None = None,
) -> list[dict[str, str]]:
    """Map accepted proposal rows to detection-repo file payloads.

    Layout: ``rules/<primary-technique|uncategorized>/<slug>.yml``. Path
    collisions (same title twice) are disambiguated with the row id suffix
    so the Git connector's duplicate-path guard never fires spuriously.

    ``final_yaml_by_row`` optionally supplies analyst-edited "final" rule bodies
    (keyed by row id) that ship instead of the stored draft — the migration-free
    draft-vs-final path (the edited text is in-memory, never a new column).
    """
    files: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in rows:
        technique = (row.technique_ids or ["uncategorized"])[0].lower()
        path = f"rules/{technique}/{_rule_slug(row.title)}.yml"
        if path in seen:
            path = f"rules/{technique}/{_rule_slug(row.title)}_{row.id[-6:].lower()}.yml"
        seen.add(path)
        files.append({"path": path, "content": _shipped_yaml(row, final_yaml_by_row)})
    return files


def _pr_body(
    rows: list[DetectionProposalRow],
    *,
    final_yaml_by_row: dict[str, str] | None = None,
) -> str:
    """Markdown PR body: a summary table + a per-rule provenance/evidence block.

    Beyond the at-a-glance table, each rule carries (issue #113 richer body):

    * an **evidence-chain SHA-256** of the exact rule body being shipped,
    * an **intel-source citation** (source STIX indicator id + bundle id),
    * a **validation hit-count** line (telemetry verdict + total hits), and
    * a **draft-vs-final note** — whether an analyst edited the rule before it
      shipped (derived by comparing the shipped body to the stored draft).
    """
    lines = [
        "Accepted Sigma rule proposals from the CTI → Detection pipeline (#113).",
        "",
        "| Rule | Techniques | Confidence | Telemetry verdict | Hits |",
        "|------|------------|------------|-------------------|------|",
    ]
    for row in rows:
        validation = row.validation or {}
        verdict = validation.get("verdict", "not validated")
        hits = validation.get("total_hits")
        hits_cell = str(hits) if hits is not None else "—"
        techniques = ", ".join(row.technique_ids or []) or "—"
        lines.append(
            f"| {row.title} | {techniques} | {row.confidence:.2f} | {verdict} | {hits_cell} |"
        )

    lines += ["", "## Provenance & evidence chain", ""]
    for row in rows:
        shipped = _shipped_yaml(row, final_yaml_by_row)
        evidence_sha = draft_evidence_sha256(shipped)
        edited = shipped.strip() != (row.sigma_yaml or "").strip()
        draft_note = "edited from draft before shipping" if edited else "unchanged from draft"
        validation = row.validation or {}
        verdict = validation.get("verdict", "not validated")
        hits = validation.get("total_hits")
        if hits is not None:
            validation_line = f"{verdict} — {hits} hit(s) over the validation window"
        else:
            validation_line = f"{verdict} (no validation run recorded)"
        lines += [
            f"### {row.title}",
            f"- Intel source: indicator `{row.source_stix_id or '—'}` "
            f"from bundle `{row.bundle_id or '—'}`",
            f"- Rule evidence SHA-256: `{evidence_sha}`",
            f"- Validation: {validation_line}",
            f"- Draft vs. final: {draft_note}",
            "",
        ]

    lines += [
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
    final_yaml_by_row: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Compose a detection-repo PR from accepted proposals (#113 slice 3).

    HITL discipline: only ``accepted`` rows (a one-shot human decision) are
    eligible, and the route gates on a senior-analyst permission — two human
    gates before anything reaches the repo. Rows that already shipped
    (non-null ``pr_url``) are refused; a rule ships once.

    ``final_yaml_by_row`` optionally supplies analyst-edited "final" rule bodies
    (keyed by row id) that ship — and are cited as *edited from draft* in the PR
    body — instead of the stored draft. This is the migration-free draft-vs-final
    path: the edited text rides in on the (in-memory) request, never a new column.

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

    # Eligible = an accepted rule, or one an analyst edited via the Engineer UI
    # (``modified``, shipping its ``final_sigma_yaml``). Both are one-shot human
    # decisions; ``proposed`` / ``rejected`` rows are not shippable.
    _shippable = {ProposalState.ACCEPTED.value, ProposalState.MODIFIED.value}
    ineligible = [r.id for r in rows if r.state not in _shippable]
    if ineligible:
        raise ValueError(
            "Only accepted or edited (modified) proposals can ship; "
            f"not eligible: {', '.join(ineligible)}"
        )
    shipped = [r.id for r in rows if r.pr_url]
    if shipped:
        raise ValueError(f"Proposal(s) already shipped in a PR: {', '.join(shipped)}")

    ordered = sorted(rows, key=lambda r: r.id)
    files = build_pr_files(ordered, final_yaml_by_row=final_yaml_by_row)
    now = _utcnow()
    branch = f"detections/cti-{now.strftime('%Y%m%d')}-{len(ordered)}-rules"
    pr_title = title or f"detections: {len(ordered)} CTI-derived Sigma rule(s)"

    # Lazy import — the Git connector lives in the agents package (mock-first;
    # live mode raises NotImplementedError until the rollout PR).
    from btagent_agents.mcp.servers.git_mcp import GitMCPServer

    envelope = await GitMCPServer().git_open_detection_pr(
        branch, pr_title, _pr_body(ordered, final_yaml_by_row=final_yaml_by_row), files
    )

    pr_url = envelope["pr_url"]
    for row in ordered:
        row.pr_url = pr_url
        # Advance the PR lifecycle: the rule is now open in a detection-repo PR
        # (#113 Phase C). A later merge outcome flips this to ``merged`` and
        # drives the closed loop (record_pr_outcome).
        row.pr_outcome = PROutcome.PR_OPENED.value
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


# ---------------------------------------------------------------------------
# Phase-C closed loop (#113): a MERGED rule installs + validates itself
#
# When a composed detection-repo PR merges, the rule is real: it should start
# hunting on a schedule (#112) AND every technique it claims should be
# re-validated by a SANDBOX-gated emulation (#118). ``record_pr_outcome`` records
# the merge and fires both, each BEST-EFFORT under its own savepoint so a hook
# failure can never roll back (sink) the merge-outcome write itself.
#
# The validation hook NEVER reaches an emulator on its own: it calls
# ``detection_emulation_service.run_emulation_validation`` with
# ``target_env=SANDBOX``, which applies the sandbox allowlist and writes the
# hash-chained audit row before anything is dispatched. A denied target yields
# no verdict and no persisted run — the gate is not bypassable from here.
# ---------------------------------------------------------------------------

from collections.abc import Awaitable, Callable  # noqa: E402

# Injectable closed-loop hooks (default impls call the real services). Injecting
# a spy lets a test assert the wiring without driving the pysigma / orchestrator
# stack — the same pattern as ``run_emulation_validation``'s ``orchestrator_run``.
HuntPackInstaller = Callable[[AsyncSession, DetectionProposalRow], Awaitable[Any]]
ValidationTrigger = Callable[[AsyncSession, str, DetectionProposalRow], Awaitable[Any]]

# Recordable PR outcomes and the one-way transitions allowed. A merge/reject may
# only be recorded once a PR is open (``pr_opened``); both are terminal.
_RECORDABLE_PR_OUTCOMES = frozenset({PROutcome.MERGED.value, PROutcome.REJECTED.value})


# Cap on how many of a merged rule's techniques are auto-emulated. A CTI-derived
# rule normally carries 1-2; the cap bounds the work a single merge can queue.
MAX_AUTO_VALIDATED_TECHNIQUES = 5


def _primary_technique(row: DetectionProposalRow) -> str | None:
    """The rule's primary ATT&CK technique — what the validation run emulates."""
    techniques = _validatable_techniques(row)
    return techniques[0] if techniques else None


def _validatable_techniques(row: DetectionProposalRow) -> list[str]:
    """Every ATT&CK technique the merged rule claims, de-duplicated and capped.

    Order-preserving so the primary technique stays first; capped at
    :data:`MAX_AUTO_VALIDATED_TECHNIQUES` so one merge cannot queue unbounded
    emulation work.
    """
    seen: set[str] = set()
    ordered: list[str] = []
    for technique in row.technique_ids or []:
        cleaned = (technique or "").strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        ordered.append(cleaned)
    return ordered[:MAX_AUTO_VALIDATED_TECHNIQUES]


async def _default_install_hunt_pack(db: AsyncSession, row: DetectionProposalRow) -> dict[str, Any]:
    """Default installer: run the merged rule as a one-off #112 hunt pack.

    Delegates to :func:`hunt_pack_run_service.run_adhoc_rule_pack` (mock-first,
    no commit) so the merged rule immediately hunts current telemetry and lands
    a :class:`HuntPackRunRow`. Returns a small descriptor for the audit detail.
    """
    from btagent_backend.services import hunt_pack_run_service

    run_row = await hunt_pack_run_service.run_adhoc_rule_pack(
        db,
        org_id=row.org_id,
        # The ad-hoc pack id becomes ``cti-merged-<row id>`` — the same label
        # ``merged_rule_pack_id`` stamps on the closed loop's validation run, so
        # install and validation are correlatable from the run history.
        rule_id=row.id,
        title=row.title,
        sigma_yaml=_shipped_yaml(row, None),
        technique_ids=list(row.technique_ids or []),
        checkpoint=False,
        emit_events=False,
    )
    return {
        "hunt_pack_run_id": run_row.run_id,
        "pack_id": run_row.pack_id,
        "findings_created": run_row.findings_created,
    }


def merged_rule_pack_id(row: DetectionProposalRow) -> str:
    """Label tying a merged rule's hunt-pack install and validation run together.

    Mirrors ``hunt_pack_run_service.run_adhoc_rule_pack``'s ``cti-merged-*``
    pack id so ``GET /validation/runs`` shows *which* merged rule a run came
    from without a schema change.
    """
    return f"cti-merged-{row.id}"


async def _default_trigger_validation(
    db: AsyncSession, actor_id: str, row: DetectionProposalRow
) -> dict[str, Any]:
    """Default validation trigger: SANDBOX-gated #118 emulation of the merged rule.

    Every technique the merged rule claims (capped at
    :data:`MAX_AUTO_VALIDATED_TECHNIQUES`) is emulated through
    :func:`detection_emulation_service.run_emulation_validation` with
    ``target_env=SANDBOX`` — the ONLY path to an emulator, so the sandbox gate,
    the hash-chained audit row, and the mock-first default all still apply
    exactly as they do for the operator-driven ``POST /validation/emulate``
    route. Nothing here bypasses that gate: a denied technique yields no
    verdict and is reported as such.

    The collected verdicts are folded into ONE ``ValidationReport`` and
    persisted to ``detection_validation_runs``, labelled with the merged rule's
    pack id, so the coverage map sees every technique of a newly merged rule as
    freshly validated. Returns a descriptor for the audit detail.
    """
    technique_ids = _validatable_techniques(row)
    if not technique_ids:
        return {"validation_triggered": False, "reason": "no technique on rule"}

    from datetime import datetime as _dt

    from btagent_shared.types.detection_validation import (
        EmulationRequest,
        Emulator,
        TargetEnv,
    )

    from btagent_backend.services import validation_run_service
    from btagent_backend.services.detection_emulation_service import run_emulation_validation
    from btagent_backend.services.validation_service import build_multi_emulation_report

    verdicts = []
    audit_ids: list[str] = []
    denied: list[str] = []
    for technique_id in technique_ids:
        request = EmulationRequest(
            technique_id=technique_id,
            target_env=TargetEnv.SANDBOX,
            emulator=Emulator.ATOMIC_RED_TEAM,
        )
        # GUARDRAIL: sandbox-gated + audited inside run_emulation_validation.
        outcome = await run_emulation_validation(
            db, actor_id=actor_id, org_id=row.org_id, request=request
        )
        audit_ids.append(outcome.audit_id)
        if not outcome.approved:
            denied.append(technique_id)
            continue
        if outcome.verdict is not None:
            verdicts.append(outcome.verdict)

    descriptor: dict[str, Any] = {
        "validation_triggered": bool(verdicts),
        "technique_id": technique_ids[0],
        "technique_ids": technique_ids,
        "target_env": TargetEnv.SANDBOX.value,
        "audit_id": audit_ids[0] if audit_ids else None,
        "audit_ids": audit_ids,
    }
    if denied:
        descriptor["denied_techniques"] = denied
    if not verdicts:
        descriptor.setdefault("reason", "no sandbox-approved verdict produced")
        return descriptor

    report = build_multi_emulation_report(
        run_id=generate_id("valrun"),
        target_env=TargetEnv.SANDBOX,
        verdicts=verdicts,
        generated_at=_dt.now(UTC),
    )
    run = await validation_run_service.persist_validation_report(
        db, report, org_id=row.org_id, packs=(merged_rule_pack_id(row),)
    )
    descriptor["validation_run_id"] = run.id
    descriptor["verdict"] = verdicts[0].verdict.value
    descriptor["verdicts"] = {v.technique_id: v.verdict.value for v in verdicts}
    return descriptor


async def _run_merge_closed_loop(
    db: AsyncSession,
    *,
    row: DetectionProposalRow,
    actor_id: str,
    install_hunt_pack: HuntPackInstaller | None,
    trigger_validation: ValidationTrigger | None,
) -> dict[str, Any]:
    """Fire the two merge hooks, each best-effort under its own savepoint.

    A hook failure is caught, logged, and reported in the returned summary — it
    NEVER propagates, so the already-flushed merge-outcome write survives. Each
    hook runs inside ``db.begin_nested()`` so a hook that writes then raises
    rolls back only its own savepoint, leaving the merge write (and the other
    hook's writes) intact.
    """
    installer = install_hunt_pack or _default_install_hunt_pack
    trigger = trigger_validation or _default_trigger_validation
    summary: dict[str, Any] = {
        "hunt_pack_installed": False,
        "validation_triggered": False,
    }

    try:
        async with db.begin_nested():
            install_detail = await installer(db, row)
        summary["hunt_pack_installed"] = True
        summary["hunt_pack"] = install_detail
    except Exception as exc:  # noqa: BLE001 — closed loop is best-effort
        logger.warning(
            "closed-loop hunt-pack install failed for merged proposal %s (non-fatal)",
            row.id,
            exc_info=True,
        )
        summary["hunt_pack_error"] = f"{type(exc).__name__}: {exc}"

    try:
        async with db.begin_nested():
            validation_detail = await trigger(db, actor_id, row)
        summary["validation_triggered"] = bool(
            validation_detail.get("validation_triggered", True)
            if isinstance(validation_detail, dict)
            else True
        )
        summary["validation"] = validation_detail
    except Exception as exc:  # noqa: BLE001 — closed loop is best-effort
        logger.warning(
            "closed-loop detection-validation trigger failed for merged proposal %s (non-fatal)",
            row.id,
            exc_info=True,
        )
        summary["validation_error"] = f"{type(exc).__name__}: {exc}"

    return summary


async def record_pr_outcome(
    db: AsyncSession,
    *,
    org_id: str,
    row_id: str,
    outcome: PROutcome,
    actor_id: str = "system",
    install_hunt_pack: HuntPackInstaller | None = None,
    trigger_validation: ValidationTrigger | None = None,
) -> tuple[DetectionProposalRow, dict[str, Any]]:
    """Record a detection-repo PR outcome for a proposal (#113 Phase C closed loop).

    Only ``merged`` / ``rejected`` are recordable, and only while a PR is open
    (``pr_outcome == 'pr_opened'``) — a rule must ship before its PR can merge,
    and the terminal outcomes are one-shot (recording twice raises). Both guards
    surface as :class:`ValueError` (route → 409); a missing / cross-org row
    raises :class:`LookupError` (route → 404).

    On ``merged`` the closed loop fires: the rule is auto-installed as a #112
    hunt-pack entry AND a #118 SANDBOX-gated detection-validation run is
    triggered for EVERY technique the rule claims (capped at
    :data:`MAX_AUTO_VALIDATED_TECHNIQUES`, folded into one persisted run) — both
    BEST-EFFORT (a hook failure never sinks the merge write). Returns
    ``(row, closed_loop_summary)``; the summary is ``{}`` for a non-merge
    outcome.

    ``install_hunt_pack`` / ``trigger_validation`` are injectable (default impls
    call the real services) so a test can assert the wiring with a spy.
    """
    if outcome.value not in _RECORDABLE_PR_OUTCOMES:
        raise ValueError(
            f"Only {sorted(_RECORDABLE_PR_OUTCOMES)} outcomes are recordable; got {outcome.value!r}"
        )

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
    if row.pr_outcome != PROutcome.PR_OPENED.value:
        raise ValueError(
            f"Cannot record {outcome.value!r}: proposal PR is not open "
            f"(pr_outcome={row.pr_outcome!r})"
        )

    row.pr_outcome = outcome.value
    row.updated_at = _utcnow()
    await db.flush()

    closed_loop: dict[str, Any] = {}
    if outcome == PROutcome.MERGED:
        closed_loop = await _run_merge_closed_loop(
            db,
            row=row,
            actor_id=actor_id,
            install_hunt_pack=install_hunt_pack,
            trigger_validation=trigger_validation,
        )
    logger.info(
        "detection proposal PR outcome recorded: row=%s outcome=%s org=%s closed_loop=%s",
        row.id,
        outcome.value,
        org_id,
        closed_loop or "<none>",
    )
    return row, closed_loop
