"""Cross-Investigation Pattern Hunter service (#120, Phase A).

Persistence + corpus-walking for the cross-investigation hunt mode. The
ranking + extraction *decisions* live in the dependency-free pure logic in
:mod:`btagent_shared.hunt.pattern`; this module is the side-effectful shell
that loads closed-investigation rows, flattens them into the pure logic's
input shape, persists the resulting weak signals + proposals, and supports
the dismiss / snooze lifecycle (which down-weights similar future surfacing).

Per the codebase convention, this service does **not** commit or emit events
— the route layer / arq job owns the single commit (see
``scheduler/jobs.py::weekly_pattern_scan``). Embedding generation is out of
scope: Phase A clusters by exact ``(kind, value)`` over the corpus, so no
vector lookup is needed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from btagent_shared.hunt import pattern as pattern_logic
from btagent_shared.types.pattern_hunt import (
    ProposalState,
    WeakSignal,
    WeakSignalCluster,
)
from btagent_shared.utils.ids import generate_id
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import (
    DEFAULT_ORG_ID,
    InvestigationRow,
    IOCRow,
    OrganizationRow,
)
from btagent_backend.db.models_pattern import PatternHuntProposalRow, WeakSignalRow

logger = logging.getLogger("btagent.services.pattern_hunt")

# Investigation statuses that count as "closed" — the corpus this hunt walks.
# Mirrors the auto-index trigger (knowledge_service indexes on close), plus
# ``remediated`` which is also a terminal, lessons-learned state.
CLOSED_STATUSES = frozenset({"closed", "remediated"})

# States that suppress a cluster from being re-proposed. A dismissed/snoozed
# proposal means the analyst has judged this shape uninteresting (for now), so
# a re-scan must not resurface it — the down-weighting mechanism.
SUPPRESSING_STATES = frozenset({ProposalState.DISMISSED.value, ProposalState.SNOOZED.value})


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _to_aware(ts: datetime) -> datetime:
    """Coerce a (possibly naive, e.g. SQLite-read) datetime to UTC-aware."""
    return ts if ts.tzinfo is not None else ts.replace(tzinfo=UTC)


# --------------------------------------------------------------------------- #
# Result shape
# --------------------------------------------------------------------------- #


@dataclass
class PatternScanResult:
    """Summary of one corpus scan — what the job logs + returns."""

    investigations_scanned: int = 0
    weak_signals_upserted: int = 0
    clusters_ranked: int = 0
    proposals_created: int = 0
    proposals_updated: int = 0
    proposals_suppressed: int = 0
    top_clusters: list[WeakSignalCluster] | None = None


@dataclass
class MultiOrgScanResult:
    """Aggregate of scanning every organization's corpus in one run.

    The weekly job runs one :func:`scan_corpus` per org (the weak-signal and
    proposal tables are org-scoped), so the per-org counts roll up here.
    """

    orgs_scanned: int = 0
    investigations_scanned: int = 0
    weak_signals_upserted: int = 0
    clusters_ranked: int = 0
    proposals_created: int = 0
    proposals_updated: int = 0


# --------------------------------------------------------------------------- #
# Corpus loading
# --------------------------------------------------------------------------- #


def _investigation_timestamp(inv: InvestigationRow) -> datetime:
    """Best recency timestamp for an investigation (closed → updated → created → now)."""
    ts = inv.closed_at or inv.updated_at or inv.created_at or _utcnow()
    return _to_aware(ts)


def _extract_cmdline_fragments(ioc: IOCRow) -> list[str]:
    """Pull cmdline fragments an IOC's context/enrichment may carry.

    Kept conservative: only explicit ``cmdline`` / ``command_line`` keys in
    enrichment (the enrichment pipeline stashes these) so we don't mistake
    arbitrary context prose for a command line.
    """
    fragments: list[str] = []
    enrichment = ioc.enrichment or {}
    for key in ("cmdline", "command_line", "process_command_line"):
        val = enrichment.get(key)
        if isinstance(val, str) and val.strip():
            fragments.append(val.strip())
    return fragments


async def load_corpus(
    db: AsyncSession,
    *,
    org_id: str = DEFAULT_ORG_ID,
) -> list[pattern_logic.ClosedInvestigationRecord]:
    """Load closed investigations + their IOCs into the pure-logic input shape.

    Org-scoped. One DB round-trip for investigations, one for their IOCs;
    flattened into :class:`ClosedInvestigationRecord` s so the pure extractor
    never touches the ORM. Asset refs come from the investigation's
    ``config`` (``assets`` / ``hosts``); ASNs + cmdline fragments from IOC
    enrichment; techniques from timeline entries are out of scope for the
    Phase A slice (IOC-driven extraction is the keystone).
    """
    inv_result = await db.execute(
        select(InvestigationRow).where(
            InvestigationRow.org_id == org_id,
            InvestigationRow.status.in_(CLOSED_STATUSES),
        )
    )
    investigations = list(inv_result.scalars().all())
    if not investigations:
        return []

    inv_ids = [inv.id for inv in investigations]
    ioc_result = await db.execute(select(IOCRow).where(IOCRow.investigation_id.in_(inv_ids)))
    iocs_by_inv: dict[str, list[IOCRow]] = {}
    for ioc in ioc_result.scalars().all():
        iocs_by_inv.setdefault(ioc.investigation_id, []).append(ioc)

    records: list[pattern_logic.ClosedInvestigationRecord] = []
    for inv in investigations:
        ts = _investigation_timestamp(inv)
        observed: list[pattern_logic.ObservedIOC] = []
        cmdline: list[str] = []
        asns: list[str] = []
        for ioc in iocs_by_inv.get(inv.id, []):
            observed.append(
                pattern_logic.ObservedIOC(
                    type=ioc.type,
                    value=ioc.value,
                    first_seen=_aware(ioc.first_seen),
                    last_seen=_aware(ioc.last_seen),
                )
            )
            cmdline.extend(_extract_cmdline_fragments(ioc))
            asn = (ioc.enrichment or {}).get("asn")
            if isinstance(asn, str | int) and str(asn).strip():
                asns.append(str(asn))

        config = inv.config or {}
        assets = _string_list(config.get("assets")) + _string_list(config.get("hosts"))
        adversaries = _string_list(config.get("adversaries"))

        records.append(
            pattern_logic.ClosedInvestigationRecord(
                investigation_id=inv.id,
                closed_at=ts,
                iocs=observed,
                techniques=[],
                cmdline_fragments=cmdline,
                assets=assets,
                asns=asns,
                adversaries=adversaries,
            )
        )
    return records


def _aware(ts: datetime | None) -> datetime | None:
    return _to_aware(ts) if ts is not None else None


def _string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if isinstance(v, str | int) and str(v).strip()]
    return []


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #


async def _upsert_weak_signals(
    db: AsyncSession,
    *,
    org_id: str,
    signals: list[WeakSignal],
) -> int:
    """Find-or-create a ``weak_signals`` row per ``(org, kind, value)``.

    On hit: refreshes first/last-seen span, refs, and the pinned diversity
    count. On miss: inserts. Returns the number of rows touched.
    """
    touched = 0
    for sig in signals:
        result = await db.execute(
            select(WeakSignalRow).where(
                WeakSignalRow.org_id == org_id,
                WeakSignalRow.kind == sig.kind.value,
                WeakSignalRow.value == sig.value,
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            row = WeakSignalRow(
                id=generate_id("ws"),
                org_id=org_id,
                kind=sig.kind.value,
                value=sig.value,
                first_seen=sig.first_seen,
                last_seen=sig.last_seen,
                investigation_refs=list(sig.investigation_refs),
                distinct_investigation_count=sig.distinct_investigation_count,
            )
            db.add(row)
        else:
            # Persisted timestamps can read back naive (SQLite) or aware
            # (Postgres ``timezone=True``); normalise both before comparing so
            # a re-scan never trips "can't compare offset-naive and aware".
            row.first_seen = min(_to_aware(row.first_seen), sig.first_seen)
            row.last_seen = max(_to_aware(row.last_seen), sig.last_seen)
            row.investigation_refs = sorted(
                set(row.investigation_refs or []) | set(sig.investigation_refs)
            )
            row.distinct_investigation_count = len(row.investigation_refs)
        touched += 1
    await db.flush()
    return touched


async def _suppressed_cluster_ids(db: AsyncSession, *, org_id: str) -> set[str]:
    """Cluster ids whose proposal is dismissed/snoozed — must not re-surface."""
    result = await db.execute(
        select(PatternHuntProposalRow.cluster_id).where(
            PatternHuntProposalRow.org_id == org_id,
            PatternHuntProposalRow.state.in_(SUPPRESSING_STATES),
        )
    )
    return {row[0] for row in result.all()}


# --------------------------------------------------------------------------- #
# Top-level scan
# --------------------------------------------------------------------------- #


async def scan_corpus(
    db: AsyncSession,
    *,
    org_id: str = DEFAULT_ORG_ID,
    initiated_by: str = "pattern_hunter",
    top_n: int = 10,
    min_distinct_investigations: int = 2,
    now: datetime | None = None,
) -> PatternScanResult:
    """Walk the closed-investigation corpus → persist weak signals + proposals.

    The single entry point the weekly job calls. Steps:

    1. Load the org's closed investigations (:func:`load_corpus`).
    2. Extract de-duplicated weak signals (pure logic) + upsert them.
    3. Rank clusters (pure logic), dropping any whose proposal the analyst has
       already dismissed/snoozed (the down-weighting of similar future
       surfacing).
    4. Upsert a ``pattern_hunt_proposals`` row per surviving top-N cluster,
       each carrying a ready-to-run ``HuntInput`` + rationale.

    Does not commit — the caller (job / route) owns the transaction.
    """
    now = now or _utcnow()
    result = PatternScanResult(top_clusters=[])

    records = await load_corpus(db, org_id=org_id)
    result.investigations_scanned = len(records)
    if not records:
        return result

    extractor = pattern_logic.WeakSignalExtractor()
    signals = extractor.extract(records)
    result.weak_signals_upserted = await _upsert_weak_signals(db, org_id=org_id, signals=signals)

    clusterer = pattern_logic.WeakSignalClusterer()
    clusters = clusterer.cluster(
        signals,
        now=now,
        top_n=None,  # rank everything, then filter suppressed, then cap
        min_distinct_investigations=min_distinct_investigations,
    )

    suppressed = await _suppressed_cluster_ids(db, org_id=org_id)
    surviving = [c for c in clusters if c.id not in suppressed]
    result.proposals_suppressed = len(clusters) - len(surviving)
    surviving = surviving[:top_n]
    result.clusters_ranked = len(surviving)
    result.top_clusters = surviving

    for cluster in surviving:
        created = await _upsert_proposal(
            db, org_id=org_id, cluster=cluster, initiated_by=initiated_by
        )
        if created:
            result.proposals_created += 1
        else:
            result.proposals_updated += 1

    logger.info(
        "pattern_hunt scan org=%s scanned=%d signals=%d ranked=%d "
        "created=%d updated=%d suppressed=%d",
        org_id,
        result.investigations_scanned,
        result.weak_signals_upserted,
        result.clusters_ranked,
        result.proposals_created,
        result.proposals_updated,
        result.proposals_suppressed,
    )
    return result


async def list_org_ids(db: AsyncSession) -> list[str]:
    """Every organization id, ascending. Falls back to the default tenant.

    The weekly scan is multi-tenant: it must walk every org's corpus, not a
    single hard-coded ``DEFAULT_ORG_ID`` (which would permanently exclude all
    other tenants). If the org table is somehow empty, fall back to the
    default so a fresh/greenfield deployment still scans something.
    """
    org_ids = list(
        (await db.execute(select(OrganizationRow.id).order_by(OrganizationRow.id))).scalars().all()
    )
    return org_ids or [DEFAULT_ORG_ID]


async def scan_all_orgs(
    db: AsyncSession,
    *,
    initiated_by: str = "pattern_hunter",
    top_n: int = 10,
    min_distinct_investigations: int = 2,
    now: datetime | None = None,
) -> MultiOrgScanResult:
    """Run :func:`scan_corpus` for **every** organization, aggregating counts.

    The decision logic the weekly job delegates to: enumerate orgs, scan each
    org-scoped corpus, and roll the per-org counts into one summary. The job
    owns the single commit (this never commits), keeping it a thin shell.
    """
    agg = MultiOrgScanResult()
    for org_id in await list_org_ids(db):
        result = await scan_corpus(
            db,
            org_id=org_id,
            initiated_by=initiated_by,
            top_n=top_n,
            min_distinct_investigations=min_distinct_investigations,
            now=now,
        )
        agg.orgs_scanned += 1
        agg.investigations_scanned += result.investigations_scanned
        agg.weak_signals_upserted += result.weak_signals_upserted
        agg.clusters_ranked += result.clusters_ranked
        agg.proposals_created += result.proposals_created
        agg.proposals_updated += result.proposals_updated
    return agg


async def _upsert_proposal(
    db: AsyncSession,
    *,
    org_id: str,
    cluster: WeakSignalCluster,
    initiated_by: str,
) -> bool:
    """Insert or refresh the proposal for ``cluster``. Returns True if created.

    A proposal still in ``proposed`` is refreshed in place (score / rationale
    / hunt_input updated) so the inbox always reflects the latest scan without
    accumulating duplicates. Accepted proposals are left untouched (the hunt
    already launched); dismissed/snoozed ones never reach here (filtered
    upstream).
    """
    # Adversaries aren't carried on WeakSignal, so HuntInput.adversaries stays
    # empty here — ttps/iocs guarantee non-emptiness. (Adversary attribution
    # surfaces in Phase B's enrichment hop.)
    hunt_input = pattern_logic.cluster_to_hunt_input(cluster, initiated_by=initiated_by)
    rationale = pattern_logic.cluster_to_proposal_rationale(cluster)

    result = await db.execute(
        select(PatternHuntProposalRow).where(
            PatternHuntProposalRow.org_id == org_id,
            PatternHuntProposalRow.cluster_id == cluster.id,
        )
    )
    row = result.scalar_one_or_none()
    now = _utcnow()
    if row is None:
        db.add(
            PatternHuntProposalRow(
                id=generate_id("phpr"),
                org_id=org_id,
                cluster_id=cluster.id,
                score=cluster.score,
                hunt_input=hunt_input.model_dump(mode="json"),
                rationale=rationale,
                state=ProposalState.PROPOSED.value,
                outcome=None,
                created_at=now,
                updated_at=now,
            )
        )
        await db.flush()
        return True

    if row.state == ProposalState.PROPOSED.value:
        row.score = cluster.score
        row.hunt_input = hunt_input.model_dump(mode="json")
        row.rationale = rationale
        row.updated_at = now
        await db.flush()
    return False


# --------------------------------------------------------------------------- #
# Lifecycle: dismiss / snooze (down-weight similar future surfacing)
# --------------------------------------------------------------------------- #


async def set_proposal_state(
    db: AsyncSession,
    *,
    proposal_id: str,
    state: ProposalState,
    triage_rationale: str = "",
) -> PatternHuntProposalRow:
    """Transition a proposal's lifecycle state.

    Dismiss/snooze flips it into a :data:`SUPPRESSING_STATES` value, which
    :func:`_suppressed_cluster_ids` reads on the next scan so the same cluster
    shape doesn't keep resurfacing. Accept marks the hunt as launched.

    Codex #218: when an analyst provides a ``triage_rationale`` we append it to
    the proposal's ``rationale`` (preceded by a delimited marker so the
    generated "why this surfaced" text remains intact). A dedicated
    ``triage_rationale`` column would be cleaner (Phase C TODO) but a
    migration is out of scope for this fix.
    """
    row = await db.get(PatternHuntProposalRow, proposal_id)
    if row is None:
        raise ValueError(f"Pattern-hunt proposal not found: {proposal_id}")
    row.state = state.value
    if triage_rationale.strip():
        marker = f"\n\n--- Analyst rationale ({state.value}) ---\n"
        row.rationale = (row.rationale or "") + marker + triage_rationale.strip()
    row.updated_at = _utcnow()
    await db.flush()
    return row


async def dismiss_proposal(
    db: AsyncSession, *, proposal_id: str, triage_rationale: str = ""
) -> PatternHuntProposalRow:
    """Mark a proposal dismissed — down-weights similar future surfacing."""
    return await set_proposal_state(
        db,
        proposal_id=proposal_id,
        state=ProposalState.DISMISSED,
        triage_rationale=triage_rationale,
    )


async def snooze_proposal(
    db: AsyncSession, *, proposal_id: str, triage_rationale: str = ""
) -> PatternHuntProposalRow:
    """Snooze a proposal — reversibly down-weights similar future surfacing."""
    return await set_proposal_state(
        db,
        proposal_id=proposal_id,
        state=ProposalState.SNOOZED,
        triage_rationale=triage_rationale,
    )
