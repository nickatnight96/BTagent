"""Audit-ledger lineage projection (UC-7.1, #110).

Projects the persisted SHA-256 hash chain in ``audit_logs`` into a node /
edge graph the analyst can navigate for forensics. Pure read-only: every
node is one ``AuditLogRow``; an edge connects each row to its
predecessor in the global chain (``prev_hash`` → ``hash``). The genesis
row has no incoming edge.

The shape mirrors the engine-tier
:class:`btagent_engine.lineage.LineageGraph` but uses the *audit-ledger*
fields (actor / action / category / seq) — those are the natural
columns for a compliance / IR consumer, not the in-flight EvidenceRecord
shape used for engine debugging.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID, AuditLogRow
from btagent_backend.services.audit_trail import (
    _GENESIS_HASH,
    _compute_hash,
    _details_to_canonical,
)


class AuditLineageNode(BaseModel):
    """One row in the audit chain, rendered as a graph node."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(..., description="Row hash; unique per entry.")
    seq: int
    timestamp: datetime
    actor: str
    category: str
    action: str
    resource: str
    outcome: str
    prev_hash: str
    sequence: int = Field(..., description="0-based position in the global chain.")


class AuditLineageEdge(BaseModel):
    """Directed edge: predecessor row → successor row."""

    model_config = ConfigDict(frozen=True)

    source: str
    target: str
    kind: str = "chain"


class AuditLineageGraph(BaseModel):
    """The lineage DAG plus chain-integrity verdict."""

    model_config = ConfigDict(frozen=True)

    nodes: tuple[AuditLineageNode, ...] = ()
    edges: tuple[AuditLineageEdge, ...] = ()
    intact: bool = True
    broken_at: str | None = Field(
        default=None,
        description="Hash of the first row that breaks the chain, or null if intact.",
    )


def _verify_row(row: AuditLogRow, expected_prev_hash: str) -> bool:
    """Re-derive a row's hash and confirm chain linkage.

    The original ``AuditTrail.record()`` builds the hash from
    ``datetime.now(UTC).isoformat()`` — a tz-aware string ending in
    ``+00:00``. Postgres preserves that on round-trip; SQLite (used by
    the in-memory test DB) drops the tzinfo, so we re-apply UTC before
    re-isoformatting to keep the recomputed hash byte-identical.
    """
    if row.prev_hash != expected_prev_hash:
        return False
    canonical = _details_to_canonical(row.details or {})
    ts = row.timestamp
    if ts is not None and ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    ts_iso = ts.isoformat() if ts else ""
    recomputed = _compute_hash(
        id=row.id,
        seq=row.seq,
        timestamp=ts_iso,
        actor=row.actor,
        category=row.category,
        action=row.action,
        resource=row.resource,
        outcome=row.outcome,
        details=canonical,
        prev_hash=row.prev_hash,
    )
    return recomputed == row.hash


def _project_rows(rows: list[AuditLogRow], *, org_id: str) -> AuditLineageGraph:
    """Project an ordered (seq ASC) list of audit rows into a lineage graph.

    Verifies the chain end-to-end; on break, surfaces the offending hash
    via ``broken_at`` while still returning the full graph so a forensics
    view can highlight exactly where tampering occurred.

    GH #385: chain linkage is verified over the *full global* row list (the
    ``prev_hash`` → ``hash`` chain spans orgs), but only rows belonging to
    ``org_id`` are projected into nodes/edges and only their breaks are
    reported — so one tenant never sees another tenant's actor/action/resource
    (nor an out-of-org hash via a dangling edge).
    """
    nodes: list[AuditLineageNode] = []
    edges: list[AuditLineageEdge] = []
    expected_prev = _GENESIS_HASH
    broken_at: str | None = None
    in_org_hashes: set[str] = set()
    position = 0  # 0-based position within the caller's scoped view

    for row in rows:
        # Linkage is checked against the global predecessor so verification
        # stays correct even though we only surface the caller's rows.
        row_ok = _verify_row(row, expected_prev)

        if row.org_id == org_id:
            nodes.append(
                AuditLineageNode(
                    id=row.hash,
                    seq=row.seq,
                    timestamp=row.timestamp,
                    actor=row.actor,
                    category=row.category,
                    action=row.action,
                    resource=row.resource or "",
                    outcome=row.outcome,
                    prev_hash=row.prev_hash,
                    sequence=position,
                )
            )
            # Only draw the edge when the predecessor is also in-scope, so we
            # never emit a dangling edge that discloses another org's hash.
            if row.prev_hash != _GENESIS_HASH and row.prev_hash in in_org_hashes:
                edges.append(AuditLineageEdge(source=row.prev_hash, target=row.hash))
            if broken_at is None and not row_ok:
                broken_at = row.hash
            in_org_hashes.add(row.hash)
            position += 1

        expected_prev = row.hash

    return AuditLineageGraph(
        nodes=tuple(nodes),
        edges=tuple(edges),
        intact=broken_at is None,
        broken_at=broken_at,
    )


async def build_audit_lineage(
    db: AsyncSession,
    *,
    org_id: str = DEFAULT_ORG_ID,
    up_to_hash: str | None = None,
) -> AuditLineageGraph:
    """Build the audit lineage graph over the persisted ledger.

    GH #385: the graph is scoped to ``org_id`` — only the caller's tenant rows
    are projected, though the underlying chain is still walked globally so
    integrity verification stays correct.

    If *up_to_hash* is provided, returns the chain prefix up to and
    including the row with that hash (UC-7.1 point-in-time replay), or
    raises :class:`LookupError` if no row matches (the API layer maps it
    to 404). The cutoff resolves only among the caller's own rows so a
    tenant cannot use it as an existence oracle for another tenant's hashes.
    """
    result = await db.execute(select(AuditLogRow).order_by(AuditLogRow.seq.asc()))
    rows = list(result.scalars().all())

    if up_to_hash is not None:
        cutoff = next(
            (i for i, r in enumerate(rows) if r.hash == up_to_hash and r.org_id == org_id),
            None,
        )
        if cutoff is None:
            raise LookupError(f"No audit entry with hash {up_to_hash!r}")
        rows = rows[: cutoff + 1]

    return _project_rows(rows, org_id=org_id)


__all__ = [
    "AuditLineageEdge",
    "AuditLineageGraph",
    "AuditLineageNode",
    "build_audit_lineage",
]
