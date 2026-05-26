"""Hunt triage service — the keystone store for Phase 6 (#119).

Companion to :mod:`btagent_backend.db.models_hunt` and
:mod:`btagent_backend.api.v1.hunt_findings`. This is the *only* place that
mutates ``hunt_findings`` / ``hunt_finding_clusters`` / ``suppression_rules``
so the cluster-on-insert, suppression-apply, and promote-to-investigation
invariants live in one place.

The clustering + suppression *decisions* are made by the dependency-free
pure logic in :mod:`btagent_shared.hunt.triage`; this module is the
side-effectful shell that loads rows, calls that logic, and writes back.
Per the codebase convention, the service never commits and never emits
events — the route layer / agent hook owns those.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from btagent_shared.hunt import triage
from btagent_shared.types.enums import Severity
from btagent_shared.types.hunt import (
    HuntFindingState,
    SuppressionState,
)
from btagent_shared.types.hunt_finding import (
    HuntEntity,
    HuntFinding,
    HuntObservable,
    SuppressionMatch,
)
from btagent_shared.utils.ids import generate_id
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import InvestigationRow
from btagent_backend.db.models_hunt import (
    HuntFindingClusterRow,
    HuntFindingRow,
    SuppressionRuleRow,
)

logger = logging.getLogger("btagent.services.hunt_triage")

# Size of the recent-findings sample used to gauge whether a proposed
# suppression rule is over-broad.
_OVERBROAD_SAMPLE_SIZE = 200
# Default re-confirmation window for suppressions created without an
# explicit one — so "suppress forever" still gets revisited.
_DEFAULT_RECONFIRM_DAYS = 90


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _as_aware_utc(dt: datetime | None) -> datetime | None:
    """Treat a naive datetime as UTC.

    Postgres ``timezone=True`` columns round-trip as aware datetimes, but
    SQLite (tests) hands them back naive. Normalising here keeps the sweep's
    comparisons tz-safe on both backends.
    """
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


# --------------------------------------------------------------------------- #
# Row <-> Pydantic
# --------------------------------------------------------------------------- #


def row_to_finding(row: HuntFindingRow) -> HuntFinding:
    """Build the dependency-free :class:`HuntFinding` from a DB row."""
    return HuntFinding(
        id=row.id,
        org_id=row.org_id,
        source=row.source,
        domain=row.domain,
        title=row.title,
        description=row.description or "",
        severity=Severity(row.severity),
        confidence=row.confidence,
        technique_ids=list(row.technique_ids or []),
        entities=[HuntEntity(**e) for e in (row.entities or [])],
        observables=[HuntObservable(**o) for o in (row.observables or [])],
        state=HuntFindingState(row.state),
        cluster_id=row.cluster_id,
        suppressed_by=row.suppressed_by,
        investigation_id=row.investigation_id,
        evidence=dict(row.evidence or {}),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def row_to_suppression(row: SuppressionRuleRow) -> SuppressionMatch:
    """Deserialise a rule's stored match criteria."""
    return SuppressionMatch.model_validate(row.match or {})


# --------------------------------------------------------------------------- #
# Cluster upsert
# --------------------------------------------------------------------------- #


async def _get_cluster(
    db: AsyncSession, *, org_id: str, signature: str
) -> HuntFindingClusterRow | None:
    result = await db.execute(
        select(HuntFindingClusterRow).where(
            HuntFindingClusterRow.org_id == org_id,
            HuntFindingClusterRow.signature == signature,
        )
    )
    return result.scalar_one_or_none()


async def _upsert_cluster_for(
    db: AsyncSession, *, finding_row: HuntFindingRow
) -> HuntFindingClusterRow:
    """Find-or-create the cluster for a finding's signature and fold it in."""
    finding = row_to_finding(finding_row)
    signature = triage.finding_signature(finding)
    finding_row.signature = signature

    cluster = await _get_cluster(db, org_id=finding_row.org_id, signature=signature)
    now = _utcnow()
    if cluster is None:
        cluster = HuntFindingClusterRow(
            id=generate_id("hclu"),
            org_id=finding_row.org_id,
            signature=signature,
            title=finding_row.title,
            domain=finding_row.domain,
            severity=finding_row.severity,
            technique_ids=list(finding_row.technique_ids or []),
            finding_count=0,
            state=HuntFindingState.CLUSTERED.value,
            representative_finding_id=finding_row.id,
            created_at=now,
            updated_at=now,
        )
        db.add(cluster)
        await db.flush()

    # Fold the new finding into the cluster's rollup.
    members = await _cluster_members(db, cluster_id=cluster.id)
    members.append(finding)  # the row isn't linked yet
    cluster.finding_count = len(members)
    cluster.severity = triage.max_severity(members).value
    cluster.technique_ids = triage.union_techniques(members)
    cluster.updated_at = now
    return cluster


async def _cluster_members(db: AsyncSession, *, cluster_id: str) -> list[HuntFinding]:
    rows = (
        await db.execute(
            select(HuntFindingRow).where(HuntFindingRow.cluster_id == cluster_id)
        )
    ).scalars().all()
    return [row_to_finding(r) for r in rows]


# --------------------------------------------------------------------------- #
# Suppression apply
# --------------------------------------------------------------------------- #


async def _active_suppressions(db: AsyncSession, *, org_id: str) -> list[SuppressionRuleRow]:
    rows = await db.execute(
        select(SuppressionRuleRow).where(
            SuppressionRuleRow.org_id == org_id,
            SuppressionRuleRow.state == SuppressionState.ACTIVE.value,
        )
    )
    return list(rows.scalars().all())


async def _apply_suppressions_to(
    db: AsyncSession, *, finding_row: HuntFindingRow, rules: list[SuppressionRuleRow]
) -> None:
    """Mark a finding suppressed if any active rule matches it."""
    finding = row_to_finding(finding_row)
    for rule in rules:
        if triage.suppression_matches(row_to_suppression(rule), finding):
            finding_row.state = HuntFindingState.SUPPRESSED.value
            finding_row.suppressed_by = rule.id
            rule.match_count += 1
            return


# --------------------------------------------------------------------------- #
# Public API — findings
# --------------------------------------------------------------------------- #


async def record_finding(
    db: AsyncSession,
    *,
    org_id: str,
    source: str,
    domain: str,
    title: str,
    description: str = "",
    severity: Severity = Severity.MEDIUM,
    confidence: float = 0.5,
    technique_ids: list[str] | None = None,
    entities: list[dict] | None = None,
    observables: list[dict] | None = None,
    evidence: dict | None = None,
) -> HuntFindingRow:
    """Insert a hunt finding, cluster it, and apply active suppressions.

    This is the entry point every hunt source funnels into. Returns the
    flushed (not committed) row, already assigned to a cluster and either
    ``CLUSTERED`` or ``SUPPRESSED``.
    """
    now = _utcnow()
    row = HuntFindingRow(
        id=generate_id("hfnd"),
        org_id=org_id,
        source=source,
        domain=domain,
        title=title,
        description=description,
        severity=severity.value if isinstance(severity, Severity) else severity,
        confidence=confidence,
        state=HuntFindingState.NEW.value,
        technique_ids=list(technique_ids or []),
        entities=list(entities or []),
        observables=list(observables or []),
        evidence=dict(evidence or {}),
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    await db.flush()

    cluster = await _upsert_cluster_for(db, finding_row=row)
    row.cluster_id = cluster.id
    row.state = HuntFindingState.CLUSTERED.value

    rules = await _active_suppressions(db, org_id=org_id)
    if rules:
        await _apply_suppressions_to(db, finding_row=row, rules=rules)

    await db.flush()
    return row


async def get_finding(db: AsyncSession, finding_id: str) -> HuntFindingRow | None:
    result = await db.execute(select(HuntFindingRow).where(HuntFindingRow.id == finding_id))
    return result.scalar_one_or_none()


async def list_clusters(
    db: AsyncSession,
    *,
    org_id: str,
    include_suppressed: bool = False,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[HuntFindingClusterRow], list[HuntFindingRow], int, int]:
    """Return the clustered triage inbox for an org.

    Clusters newest-first, plus the member findings for the returned
    clusters. Suppressed findings are excluded unless ``include_suppressed``.
    """
    offset = (page - 1) * page_size

    count_q = (
        select(func.count())
        .select_from(HuntFindingClusterRow)
        .where(HuntFindingClusterRow.org_id == org_id)
    )
    total_clusters = (await db.execute(count_q)).scalar_one() or 0

    cluster_rows = (
        await db.execute(
            select(HuntFindingClusterRow)
            .where(HuntFindingClusterRow.org_id == org_id)
            .order_by(HuntFindingClusterRow.updated_at.desc())
            .offset(offset)
            .limit(page_size)
        )
    ).scalars().all()

    cluster_ids = [c.id for c in cluster_rows]
    findings: list[HuntFindingRow] = []
    if cluster_ids:
        finding_q = select(HuntFindingRow).where(HuntFindingRow.cluster_id.in_(cluster_ids))
        if not include_suppressed:
            finding_q = finding_q.where(
                HuntFindingRow.state != HuntFindingState.SUPPRESSED.value
            )
        finding_q = finding_q.order_by(HuntFindingRow.created_at.desc())
        findings = list((await db.execute(finding_q)).scalars().all())

    total_findings_q = (
        select(func.count())
        .select_from(HuntFindingRow)
        .where(HuntFindingRow.org_id == org_id)
    )
    if not include_suppressed:
        total_findings_q = total_findings_q.where(
            HuntFindingRow.state != HuntFindingState.SUPPRESSED.value
        )
    total_findings = (await db.execute(total_findings_q)).scalar_one() or 0

    return list(cluster_rows), findings, int(total_clusters), int(total_findings)


# --------------------------------------------------------------------------- #
# Public API — suppression
# --------------------------------------------------------------------------- #


class OverbroadSuppressionError(ValueError):
    """Raised when a proposed suppression rule would hide too much."""


async def create_suppression(
    db: AsyncSession,
    *,
    org_id: str,
    name: str,
    reason: str,
    match: SuppressionMatch,
    created_by: str | None,
    expires_in_hours: int | None = None,
    reconfirm_in_hours: int | None = None,
) -> tuple[SuppressionRuleRow, int]:
    """Create a suppression rule and apply it to existing matching findings.

    Guards against over-broad rules (see
    :func:`btagent_shared.hunt.triage.is_overbroad`) by sampling recent
    findings; raises :class:`OverbroadSuppressionError` if the rule would
    match too large / too diverse a slice. Returns the rule and the count
    of findings it suppressed on creation.
    """
    sample_rows = (
        await db.execute(
            select(HuntFindingRow)
            .where(HuntFindingRow.org_id == org_id)
            .order_by(HuntFindingRow.created_at.desc())
            .limit(_OVERBROAD_SAMPLE_SIZE)
        )
    ).scalars().all()
    sample = [row_to_finding(r) for r in sample_rows]

    overbroad, why = triage.is_overbroad(match, sample)
    if overbroad:
        raise OverbroadSuppressionError(why)

    now = _utcnow()
    expires_at = now + timedelta(hours=expires_in_hours) if expires_in_hours else None
    if reconfirm_in_hours:
        reconfirm_at = now + timedelta(hours=reconfirm_in_hours)
    else:
        reconfirm_at = now + timedelta(days=_DEFAULT_RECONFIRM_DAYS)

    rule = SuppressionRuleRow(
        id=generate_id("supp"),
        org_id=org_id,
        name=name,
        reason=reason,
        match=match.model_dump(mode="json"),
        state=SuppressionState.ACTIVE.value,
        match_count=0,
        created_by=created_by,
        created_at=now,
        expires_at=expires_at,
        reconfirm_at=reconfirm_at,
    )
    db.add(rule)
    await db.flush()

    # Apply to existing non-terminal findings in the org.
    existing = (
        await db.execute(
            select(HuntFindingRow).where(
                HuntFindingRow.org_id == org_id,
                HuntFindingRow.state.in_(
                    [
                        HuntFindingState.NEW.value,
                        HuntFindingState.CLUSTERED.value,
                        HuntFindingState.TRIAGED.value,
                    ]
                ),
            )
        )
    ).scalars().all()

    suppressed = 0
    for frow in existing:
        if triage.suppression_matches(match, row_to_finding(frow)):
            frow.state = HuntFindingState.SUPPRESSED.value
            frow.suppressed_by = rule.id
            suppressed += 1
    rule.match_count = suppressed
    await db.flush()
    return rule, suppressed


async def list_suppressions(db: AsyncSession, *, org_id: str) -> list[SuppressionRuleRow]:
    rows = await db.execute(
        select(SuppressionRuleRow)
        .where(SuppressionRuleRow.org_id == org_id)
        .order_by(SuppressionRuleRow.created_at.desc())
    )
    return list(rows.scalars().all())


async def sweep_stale_suppressions(
    db: AsyncSession, *, now: datetime | None = None
) -> dict[str, int]:
    """Flip expired / due-for-reconfirmation suppressions (arq cron entry).

    ``ACTIVE`` rules past ``expires_at`` → ``EXPIRED``; past ``reconfirm_at``
    → ``NEEDS_RECONFIRM``. Returns counts for observability. Findings
    suppressed by a now-inactive rule are left as-is (re-evaluating them is
    a separate, heavier pass); the point of the sweep is to force a human
    to re-affirm the rule before it keeps hiding new signal.
    """
    now = now or _utcnow()
    rows = (
        await db.execute(
            select(SuppressionRuleRow).where(
                SuppressionRuleRow.state == SuppressionState.ACTIVE.value
            )
        )
    ).scalars().all()

    expired = 0
    needs_reconfirm = 0
    for rule in rows:
        expires_at = _as_aware_utc(rule.expires_at)
        reconfirm_at = _as_aware_utc(rule.reconfirm_at)
        if expires_at is not None and expires_at <= now:
            rule.state = SuppressionState.EXPIRED.value
            expired += 1
        elif reconfirm_at is not None and reconfirm_at <= now:
            rule.state = SuppressionState.NEEDS_RECONFIRM.value
            needs_reconfirm += 1

    await db.flush()
    return {"expired": expired, "needs_reconfirm": needs_reconfirm, "scanned": len(rows)}


# --------------------------------------------------------------------------- #
# Public API — promotion
# --------------------------------------------------------------------------- #


async def promote_to_investigation(
    db: AsyncSession,
    *,
    org_id: str,
    finding_ids: list[str],
    title: str | None,
    assigned_to: str | None,
) -> tuple[InvestigationRow, list[str]]:
    """Escalate one or more findings into a new investigation.

    Seeds the investigation with the union of the findings' observables,
    technique mapping, and evidence provenance, and flips each finding to
    ``PROMOTED`` with a back-reference. Raises :class:`ValueError` if no
    in-scope findings are resolved (route surfaces 404).
    """
    rows = (
        await db.execute(
            select(HuntFindingRow).where(
                HuntFindingRow.id.in_(finding_ids),
                HuntFindingRow.org_id == org_id,
            )
        )
    ).scalars().all()
    if not rows:
        raise ValueError("No in-scope hunt findings resolved for promotion")

    findings = [row_to_finding(r) for r in rows]
    severity = triage.max_severity(findings)
    techniques = triage.union_techniques(findings)
    observables = [o.model_dump() for f in findings for o in f.observables]

    inv_title = title or f"Hunt promotion: {rows[0].title}"
    now = _utcnow()
    inv = InvestigationRow(
        id=generate_id("inv"),
        org_id=org_id,
        title=inv_title,
        description=(
            f"Promoted from {len(rows)} hunt finding(s) "
            f"via the Phase 6 triage agent."
        ),
        severity=severity.value,
        tlp_level="amber",
        status="pending",
        assigned_to=assigned_to,
        config={
            "origin": "hunt_promotion",
            "hunt_finding_ids": [r.id for r in rows],
            "mitre_techniques": techniques,
            "observables": observables,
            "evidence": [f.evidence for f in findings if f.evidence],
        },
        created_at=now,
        updated_at=now,
    )
    db.add(inv)
    await db.flush()

    for r in rows:
        r.state = HuntFindingState.PROMOTED.value
        r.investigation_id = inv.id
    await db.flush()

    return inv, [r.id for r in rows]
