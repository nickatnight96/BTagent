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
events — the route layer / agent hook owns those. Suppress / promote *are*
audited here (category ``hunt``), matching the workflow_service idiom of
recording lifecycle transitions next to the mutation they describe.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from btagent_shared.hunt import triage
from btagent_shared.types.enums import AuditCategory, AuditOutcome, Severity, UserRole
from btagent_shared.types.hunt import (
    HuntFindingState,
    SuppressionState,
)
from btagent_shared.types.hunt_finding import (
    HuntEntity,
    HuntFinding,
    HuntObservable,
    RecordFindingRequest,
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
from btagent_backend.services.audit_trail import AuditTrail

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

    # Codex #199: if a new finding arrives for a cluster previously marked
    # PROMOTED or SUPPRESSED, the new signal must not be silently absorbed
    # into an "already handled" aggregate state. Reopen to CLUSTERED so it
    # surfaces for triage again. PROMOTED reopens because the prior
    # promotion's investigation still exists (preserved in audit) but a
    # NEW finding warrants its own analyst decision. SUPPRESSED only
    # reaches here when ``_active_suppressions`` produced no match — i.e.
    # the rule that originally suppressed the cluster has expired or been
    # withdrawn; reopen so the lapsed suppression isn't a permanent blind
    # spot.
    if cluster.state in (
        HuntFindingState.PROMOTED.value,
        HuntFindingState.SUPPRESSED.value,
    ):
        cluster.state = HuntFindingState.CLUSTERED.value
    return cluster


async def _cluster_members(db: AsyncSession, *, cluster_id: str) -> list[HuntFinding]:
    rows = (
        (await db.execute(select(HuntFindingRow).where(HuntFindingRow.cluster_id == cluster_id)))
        .scalars()
        .all()
    )
    return [row_to_finding(r) for r in rows]


async def _recompute_cluster_states(db: AsyncSession, *, cluster_ids: set[str]) -> None:
    """Roll an individual finding action up to its parent cluster (Codex PR#201 P1).

    An individually suppressed/promoted finding used to leave its parent
    cluster untouched, so the cluster never appeared in the matching state tab
    and the member silently vanished. After such an action we recompute each
    affected cluster's aggregate over its **non-dismissed** members:

    * all remaining members ``SUPPRESSED`` → cluster ``SUPPRESSED``
    * all remaining members ``PROMOTED`` → cluster ``PROMOTED``
    * a mix (or any still-active member) → cluster ``CLUSTERED``

    This mirrors the spirit of the ingest reopen logic in
    :func:`_upsert_cluster_for` (which drags terminal clusters back to
    ``CLUSTERED`` on a fresh member) and of :func:`suppress_cluster`'s
    all-members-suppressed flip — they must stay consistent. Audit rows are
    unchanged: this is a derived-state reconciliation, not a new action.
    """
    for cluster_id in cluster_ids:
        cluster = await get_cluster(db, cluster_id)
        if cluster is None:
            continue
        member_states = [
            row.state
            for row in (
                await db.execute(
                    select(HuntFindingRow).where(HuntFindingRow.cluster_id == cluster_id)
                )
            )
            .scalars()
            .all()
        ]
        considered = [s for s in member_states if s != HuntFindingState.DISMISSED.value]
        if not considered:
            continue
        if all(s == HuntFindingState.SUPPRESSED.value for s in considered):
            new_state = HuntFindingState.SUPPRESSED.value
        elif all(s == HuntFindingState.PROMOTED.value for s in considered):
            new_state = HuntFindingState.PROMOTED.value
        else:
            new_state = HuntFindingState.CLUSTERED.value
        if cluster.state != new_state:
            cluster.state = new_state
            cluster.updated_at = _utcnow()


# --------------------------------------------------------------------------- #
# Suppression apply
# --------------------------------------------------------------------------- #


async def _active_suppressions(db: AsyncSession, *, org_id: str) -> list[SuppressionRuleRow]:
    """Rules that may suppress a new finding: ``ACTIVE`` *and* not yet expired.

    The state flip to ``EXPIRED`` happens in :func:`sweep_stale_suppressions`
    (a cron), so a rule can sit past its ``expires_at`` while still marked
    ``ACTIVE``. Expiry is checked here at ingest time so a lapsed rule never
    hides a new finding just because the sweep hasn't run yet.
    """
    rows = await db.execute(
        select(SuppressionRuleRow).where(
            SuppressionRuleRow.org_id == org_id,
            SuppressionRuleRow.state == SuppressionState.ACTIVE.value,
        )
    )
    now = _utcnow()
    active: list[SuppressionRuleRow] = []
    for rule in rows.scalars().all():
        expires_at = _as_aware_utc(rule.expires_at)
        if expires_at is not None and expires_at <= now:
            continue
        active.append(rule)
    return active


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


async def persist_hunt_findings(
    db: AsyncSession,
    *,
    org_id: str,
    findings: list[RecordFindingRequest],
) -> list[HuntFindingRow]:
    """Persist a batch of runner-emitted findings into the #119 store.

    Each is clustered + suppression-checked on insert via
    :func:`record_finding`. Used by the Hunt Pack Runner's scheduled job to
    land its hits in the triage queue. Returns the created rows (not committed).
    """
    rows: list[HuntFindingRow] = []
    for req in findings:
        rows.append(
            await record_finding(
                db,
                org_id=org_id,
                source=req.source.value,
                domain=req.domain.value,
                title=req.title,
                description=req.description,
                severity=req.severity,
                confidence=req.confidence,
                technique_ids=req.technique_ids,
                entities=[e.model_dump() for e in req.entities],
                observables=[o.model_dump() for o in req.observables],
                evidence=req.evidence,
            )
        )
    return rows


async def get_finding(db: AsyncSession, finding_id: str) -> HuntFindingRow | None:
    result = await db.execute(select(HuntFindingRow).where(HuntFindingRow.id == finding_id))
    return result.scalar_one_or_none()


# Codex PR#201 P1: the ``state`` query param maps to a cluster-state
# predicate applied BEFORE pagination (so tabs don't filter a single page
# client-side and produce empty pages / wrong totals). ``active`` covers the
# two non-terminal cluster states (a cluster is created CLUSTERED and only a
# fresh-ingest reopen could leave it NEW-shaped); ``suppressed`` / ``promoted``
# are exact terminal-state matches. ``all`` (the default) applies no filter,
# preserving the pre-existing behaviour for current consumers.
_CLUSTER_STATE_FILTERS: dict[str, tuple[str, ...]] = {
    "active": (HuntFindingState.NEW.value, HuntFindingState.CLUSTERED.value),
    "suppressed": (HuntFindingState.SUPPRESSED.value,),
    "promoted": (HuntFindingState.PROMOTED.value,),
}


async def list_clusters(
    db: AsyncSession,
    *,
    org_id: str,
    include_suppressed: bool = False,
    state: str | None = None,
    domain: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[HuntFindingClusterRow], list[HuntFindingRow], int, int]:
    """Return the clustered triage inbox for an org.

    Clusters newest-first, plus the member findings for the returned
    clusters. Suppressed *findings* are excluded unless ``include_suppressed``.

    ``state`` filters on the **cluster** aggregate state and is applied to the
    cluster query (and its count) BEFORE pagination, so a state tab shows the
    right page and the right total (Codex PR#201 P1). Accepted values:
    ``active`` (NEW/CLUSTERED), ``suppressed``, ``promoted``, ``all`` /
    ``None`` (no filter — the default, back-compatible behaviour). Precedence
    with ``include_suppressed``: an explicit ``state`` wins; when ``state`` is
    unset the legacy ``include_suppressed`` flag still governs which member
    findings are returned.
    """
    offset = (page - 1) * page_size

    state_filter = _CLUSTER_STATE_FILTERS.get(state) if state and state != "all" else None

    count_q = (
        select(func.count())
        .select_from(HuntFindingClusterRow)
        .where(HuntFindingClusterRow.org_id == org_id)
    )
    if state_filter is not None:
        count_q = count_q.where(HuntFindingClusterRow.state.in_(state_filter))
    # ``domain`` (Codex #216/#217 P1): filter by HuntDomain on the cluster
    # row server-side, so the per-domain hunt views get correct totals + the
    # right slice on every page instead of paging through cross-domain noise.
    if domain is not None:
        count_q = count_q.where(HuntFindingClusterRow.domain == domain)
    total_clusters = (await db.execute(count_q)).scalar_one() or 0

    cluster_q = (
        select(HuntFindingClusterRow)
        .where(HuntFindingClusterRow.org_id == org_id)
        .order_by(HuntFindingClusterRow.updated_at.desc())
    )
    if state_filter is not None:
        cluster_q = cluster_q.where(HuntFindingClusterRow.state.in_(state_filter))
    if domain is not None:
        cluster_q = cluster_q.where(HuntFindingClusterRow.domain == domain)
    cluster_rows = (await db.execute(cluster_q.offset(offset).limit(page_size))).scalars().all()

    # Whether suppressed *member findings* are returned. The ``suppressed`` /
    # ``promoted`` tabs explicitly want their slice's members verbatim (a
    # ``suppressed`` tab would be empty otherwise), so they override the legacy
    # ``include_suppressed=false`` default. ``active``, ``all`` and the
    # no-``state`` default keep the legacy behaviour: suppressed findings are
    # hidden unless ``include_suppressed`` is set. (``all`` must NOT imply
    # show-suppressed — it is the back-compatible default the existing inbox
    # sends, which has always hidden suppressed findings.)
    show_suppressed = include_suppressed or state in ("suppressed", "promoted")

    cluster_ids = [c.id for c in cluster_rows]
    findings: list[HuntFindingRow] = []
    if cluster_ids:
        finding_q = select(HuntFindingRow).where(HuntFindingRow.cluster_id.in_(cluster_ids))
        if not show_suppressed:
            finding_q = finding_q.where(HuntFindingRow.state != HuntFindingState.SUPPRESSED.value)
        finding_q = finding_q.order_by(HuntFindingRow.created_at.desc())
        findings = list((await db.execute(finding_q)).scalars().all())

    total_findings_q = (
        select(func.count()).select_from(HuntFindingRow).where(HuntFindingRow.org_id == org_id)
    )
    if not show_suppressed:
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
    actor: str | None = None,
    target: str | None = None,
    expires_in_hours: int | None = None,
    reconfirm_in_hours: int | None = None,
    acknowledge_overbroad: bool = False,
    caller_role: str | None = None,
) -> tuple[SuppressionRuleRow, int]:
    """Create a suppression rule and apply it to existing matching findings.

    A non-blank ``reason`` (the analyst's rationale) is mandatory — every
    suppression must be defensible on the audit ledger; raises
    :class:`ValueError` otherwise. Guards against over-broad rules (see
    :func:`btagent_shared.hunt.triage.is_overbroad`) by sampling recent
    findings; raises :class:`OverbroadSuppressionError` if the rule would
    match too large / too diverse a slice.

    When ``acknowledge_overbroad=True`` and the caller holds the
    ``incident_commander`` or ``admin`` role (``caller_role``), an over-broad
    rule is allowed through with an extra audit entry recording the override.
    Lower roles and unauthenticated callers are still rejected.

    Records the action on the hash-chain audit log (category ``hunt`` /
    action ``suppress``; ``actor`` defaults to ``created_by``). Returns the
    rule and the count of findings it suppressed on creation.
    """
    if not reason or not reason.strip():
        raise ValueError("Suppression rationale (reason) is required and must not be blank")

    sample_rows = (
        (
            await db.execute(
                select(HuntFindingRow)
                .where(HuntFindingRow.org_id == org_id)
                .order_by(HuntFindingRow.created_at.desc())
                .limit(_OVERBROAD_SAMPLE_SIZE)
            )
        )
        .scalars()
        .all()
    )
    sample = [row_to_finding(r) for r in sample_rows]

    overbroad, why = triage.is_overbroad(match, sample)
    overbroad_acknowledged = False
    if overbroad:
        # Allow IC/admin to override the overbroad gate when they explicitly
        # acknowledge it. All other callers (including unauthenticated) are
        # hard-rejected regardless of the flag.
        _elevated_roles = {UserRole.INCIDENT_COMMANDER.value, UserRole.ADMIN.value}
        if acknowledge_overbroad and caller_role in _elevated_roles:
            overbroad_acknowledged = True
            logger.warning(
                "Over-broad suppression acknowledged by elevated role %s: %s",
                caller_role,
                why,
            )
        else:
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
        harmful_flag=False,
        harmful_reason=None,
        harmful_finding_id=None,
    )
    db.add(rule)
    await db.flush()

    # Apply to existing non-terminal findings in the org.
    existing = (
        (
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
        )
        .scalars()
        .all()
    )

    suppressed = 0
    touched_clusters: set[str] = set()
    for frow in existing:
        if triage.suppression_matches(match, row_to_finding(frow)):
            frow.state = HuntFindingState.SUPPRESSED.value
            frow.suppressed_by = rule.id
            suppressed += 1
            if frow.cluster_id:
                touched_clusters.add(frow.cluster_id)
    rule.match_count = suppressed

    # Codex PR#201 P1: roll the individual suppressions up to their parent
    # clusters so a cluster whose members are now all suppressed flips to
    # SUPPRESSED (and shows in the suppressed tab). ``suppress_cluster`` does
    # its own flush-time flip; this covers finding-level / standalone-rule
    # suppression. Must run before the flush below.
    if touched_clusters:
        await _recompute_cluster_states(db, cluster_ids=touched_clusters)

    audit_details: dict = {
        "org_id": org_id,
        "name": name,
        "reason": reason,
        "match": match.model_dump(mode="json"),
        "suppressed_count": suppressed,
        "target": target,
        "expires_at": expires_at.isoformat() if expires_at else None,
    }
    if overbroad_acknowledged:
        audit_details["overbroad_acknowledged"] = True
        audit_details["overbroad_reason"] = why
        audit_details["approver_role"] = caller_role

    await AuditTrail(db).record(
        actor=actor or created_by or "system",
        category=AuditCategory.HUNT,
        action="suppress",
        resource=f"suppression:{rule.id}",
        outcome=AuditOutcome.SUCCESS,
        details=audit_details,
    )
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
    # Normalise a caller-supplied `now` to aware-UTC too: the stored
    # expires_at/reconfirm_at are coerced to aware via _as_aware_utc below, so
    # a naive `now` would raise "can't compare offset-naive and offset-aware".
    now = _as_aware_utc(now) or _utcnow()
    rows = (
        (
            await db.execute(
                select(SuppressionRuleRow).where(
                    SuppressionRuleRow.state == SuppressionState.ACTIVE.value
                )
            )
        )
        .scalars()
        .all()
    )

    audit = AuditTrail(db)
    expired = 0
    needs_reconfirm = 0
    for rule in rows:
        expires_at = _as_aware_utc(rule.expires_at)
        reconfirm_at = _as_aware_utc(rule.reconfirm_at)
        if expires_at is not None and expires_at <= now:
            rule.state = SuppressionState.EXPIRED.value
            expired += 1
            await _audit_sweep_flip(audit, rule=rule, action="suppression_expired")
        elif reconfirm_at is not None and reconfirm_at <= now:
            rule.state = SuppressionState.NEEDS_RECONFIRM.value
            needs_reconfirm += 1
            await _audit_sweep_flip(audit, rule=rule, action="suppression_needs_reconfirm")

    await db.flush()
    return {"expired": expired, "needs_reconfirm": needs_reconfirm, "scanned": len(rows)}


async def _audit_sweep_flip(audit: AuditTrail, *, rule: SuppressionRuleRow, action: str) -> None:
    """Record one sweep-driven suppression state flip on the audit chain.

    The sweep is a system (cron) actor — no analyst is in the loop — so the
    flip must still be defensible on the ledger (a suppression silently
    expiring or being re-flagged is a control-state change). Category
    ``hunt``; action ``suppression_expired`` / ``suppression_needs_reconfirm``.
    """
    await audit.record(
        actor="system:suppression_sweep",
        category=AuditCategory.HUNT,
        action=action,
        resource=f"suppression:{rule.id}",
        outcome=AuditOutcome.SUCCESS,
        details={
            "org_id": rule.org_id,
            "name": rule.name,
            "new_state": rule.state,
            "expires_at": rule.expires_at.isoformat() if rule.expires_at else None,
            "reconfirm_at": rule.reconfirm_at.isoformat() if rule.reconfirm_at else None,
        },
    )


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
    actor: str | None = None,
) -> tuple[InvestigationRow, list[str]]:
    """Escalate one or more findings into a new investigation.

    Seeds the investigation with the union of the findings' observables,
    technique mapping, and evidence provenance, and flips each finding to
    ``PROMOTED`` with a back-reference. Records the escalation on the
    hash-chain audit log (category ``hunt`` / action ``promote``; ``actor``
    defaults to ``assigned_to``). Raises :class:`ValueError` if no
    in-scope findings are resolved (route surfaces 404).
    """
    rows = (
        (
            await db.execute(
                select(HuntFindingRow).where(
                    HuntFindingRow.id.in_(finding_ids),
                    HuntFindingRow.org_id == org_id,
                )
            )
        )
        .scalars()
        .all()
    )
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
        description=(f"Promoted from {len(rows)} hunt finding(s) via the Phase 6 triage agent."),
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

    touched_clusters: set[str] = set()
    for r in rows:
        r.state = HuntFindingState.PROMOTED.value
        r.investigation_id = inv.id
        if r.cluster_id:
            touched_clusters.add(r.cluster_id)

    # Codex PR#201 P1: roll finding-level promotions up to the parent cluster
    # so a cluster whose non-dismissed members are now all promoted flips to
    # PROMOTED (and leaves the active tab). ``promote_cluster`` sets the
    # cluster state itself; this covers the finding-level promote path. A
    # partial promotion leaves the cluster CLUSTERED. Runs before the flush.
    if touched_clusters:
        await _recompute_cluster_states(db, cluster_ids=touched_clusters)

    # Phase C (#119): harmful-suppression detection. Any active suppression rule
    # whose match criteria would have matched one of the promoted findings is
    # flagged as harmful — it was hiding real threat signal.
    active_rules = await _active_suppressions(db, org_id=org_id)
    if active_rules:
        rule_ids = [r.id for r in active_rules]
        rule_matches = [row_to_suppression(r) for r in active_rules]
        harmful_ids = triage.harmful_suppressions(rule_matches, rule_ids, findings)
        if harmful_ids:
            harmful_set = set(harmful_ids)
            for rule in active_rules:
                # Only the FIRST promotion that proves a rule harmful records the
                # trigger: harmful_reason / harmful_finding_id track the original
                # finding, and we avoid emitting a duplicate flagged-harmful audit
                # event when an already-flagged rule matches a later promotion.
                if rule.id in harmful_set and not rule.harmful_flag:
                    first_finding = next(
                        f
                        for f in findings
                        if triage.suppression_matches(row_to_suppression(rule), f)
                    )
                    harm_reason = (
                        f"Suppression '{rule.name}' matched finding '{first_finding.id}' "
                        f"promoted to investigation '{inv.id}' by "
                        f"{actor or assigned_to or 'system'}"
                    )
                    rule.harmful_flag = True
                    rule.harmful_reason = harm_reason
                    rule.harmful_finding_id = first_finding.id
                    await AuditTrail(db).record(
                        actor=actor or assigned_to or "system",
                        category=AuditCategory.HUNT,
                        action="suppression_flagged_harmful",
                        resource=f"suppression:{rule.id}",
                        outcome=AuditOutcome.SUCCESS,
                        details={
                            "org_id": org_id,
                            "suppression_name": rule.name,
                            "harmful_reason": harm_reason,
                            "harmful_finding_id": first_finding.id,
                            "investigation_id": inv.id,
                        },
                    )

    await AuditTrail(db).record(
        actor=actor or assigned_to or "system",
        category=AuditCategory.HUNT,
        action="promote",
        resource=f"investigation:{inv.id}",
        outcome=AuditOutcome.SUCCESS,
        details={
            "org_id": org_id,
            "title": inv_title,
            "severity": severity.value,
            "hunt_finding_ids": [r.id for r in rows],
            "mitre_techniques": techniques,
        },
    )
    await db.flush()

    return inv, [r.id for r in rows]


# --------------------------------------------------------------------------- #
# Public API — cluster-level actions
# --------------------------------------------------------------------------- #


async def get_cluster(db: AsyncSession, cluster_id: str) -> HuntFindingClusterRow | None:
    result = await db.execute(
        select(HuntFindingClusterRow).where(HuntFindingClusterRow.id == cluster_id)
    )
    return result.scalar_one_or_none()


async def suppress_cluster(
    db: AsyncSession,
    *,
    org_id: str,
    cluster: HuntFindingClusterRow,
    name: str,
    reason: str,
    match: SuppressionMatch | None,
    created_by: str | None,
    actor: str | None = None,
    expires_in_hours: int | None = None,
    reconfirm_in_hours: int | None = None,
    acknowledge_overbroad: bool = False,
    caller_role: str | None = None,
) -> tuple[SuppressionRuleRow, int]:
    """Bulk-suppress a cluster: one rule covering the cluster's pattern.

    When ``match`` is omitted it is derived from the members (domain +
    technique set — see :func:`btagent_shared.hunt.triage.match_for_cluster`)
    so the rule keeps suppressing the recurring pattern, not just today's
    members. The supplied/derived match must apply to the cluster's members
    (:class:`ValueError` otherwise — guards pasting the wrong criteria), and
    the usual over-broad gate applies. The cluster row itself is flipped to
    ``SUPPRESSED`` when every member is suppressed.

    ``acknowledge_overbroad`` and ``caller_role`` are forwarded to
    :func:`create_suppression` for the IC-gated override path.
    """
    members = await _cluster_members(db, cluster_id=cluster.id)
    if match is None:
        match = triage.match_for_cluster(members)
    elif members and not any(triage.suppression_matches(match, m) for m in members):
        raise ValueError("Suppression match does not apply to any finding in the cluster")

    rule, suppressed = await create_suppression(
        db,
        org_id=org_id,
        name=name,
        reason=reason,
        match=match,
        created_by=created_by,
        actor=actor,
        target=f"hunt_cluster:{cluster.id}",
        expires_in_hours=expires_in_hours,
        reconfirm_in_hours=reconfirm_in_hours,
        acknowledge_overbroad=acknowledge_overbroad,
        caller_role=caller_role,
    )

    member_rows = (
        (await db.execute(select(HuntFindingRow).where(HuntFindingRow.cluster_id == cluster.id)))
        .scalars()
        .all()
    )
    if member_rows and all(
        m.state in (HuntFindingState.SUPPRESSED.value, HuntFindingState.DISMISSED.value)
        for m in member_rows
    ):
        cluster.state = HuntFindingState.SUPPRESSED.value
        cluster.updated_at = _utcnow()
    await db.flush()
    return rule, suppressed


async def promote_cluster(
    db: AsyncSession,
    *,
    org_id: str,
    cluster: HuntFindingClusterRow,
    title: str | None,
    assigned_to: str | None,
    actor: str | None = None,
) -> tuple[InvestigationRow, list[str]]:
    """Escalate a cluster's non-terminal members into one investigation.

    Members already ``PROMOTED`` or ``DISMISSED`` are left alone; everything
    else (including suppressed members — promoting a cluster is an explicit
    human override) rides into the new investigation. Raises
    :class:`ValueError` if the cluster has no promotable members.
    """
    member_rows = (
        (
            await db.execute(
                select(HuntFindingRow).where(
                    HuntFindingRow.cluster_id == cluster.id,
                    HuntFindingRow.org_id == org_id,
                    HuntFindingRow.state.not_in(
                        [HuntFindingState.PROMOTED.value, HuntFindingState.DISMISSED.value]
                    ),
                )
            )
        )
        .scalars()
        .all()
    )
    if not member_rows:
        raise ValueError("Cluster has no findings eligible for promotion")

    inv, promoted = await promote_to_investigation(
        db,
        org_id=org_id,
        finding_ids=[m.id for m in member_rows],
        title=title or f"Hunt promotion: {cluster.title}",
        assigned_to=assigned_to,
        actor=actor,
    )
    cluster.state = HuntFindingState.PROMOTED.value
    cluster.updated_at = _utcnow()
    await db.flush()
    return inv, promoted
