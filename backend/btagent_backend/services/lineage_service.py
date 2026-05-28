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

from btagent_backend.db.models import AuditLogRow
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


def _project_rows(rows: list[AuditLogRow]) -> AuditLineageGraph:
    """Project an ordered (seq ASC) list of audit rows into a lineage graph.

    Verifies the chain end-to-end; on break, surfaces the offending hash
    via ``broken_at`` while still returning the full graph so a forensics
    view can highlight exactly where tampering occurred.
    """
    nodes: list[AuditLineageNode] = []
    edges: list[AuditLineageEdge] = []
    expected_prev = _GENESIS_HASH
    broken_at: str | None = None

    for seq, row in enumerate(rows):
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
                sequence=seq,
            )
        )
        if row.prev_hash != _GENESIS_HASH:
            edges.append(AuditLineageEdge(source=row.prev_hash, target=row.hash))

        if broken_at is None and not _verify_row(row, expected_prev):
            broken_at = row.hash
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
    up_to_hash: str | None = None,
) -> AuditLineageGraph:
    """Build the audit lineage graph over the persisted ledger.

    If *up_to_hash* is provided, returns the chain prefix up to and
    including the row with that hash (UC-7.1 point-in-time replay). If
    no row matches, the full graph is returned (caller may treat that as
    a not-found at the API layer).
    """
    result = await db.execute(select(AuditLogRow).order_by(AuditLogRow.seq.asc()))
    rows = list(result.scalars().all())

    if up_to_hash is not None:
        cutoff = next((i for i, r in enumerate(rows) if r.hash == up_to_hash), None)
        if cutoff is not None:
            rows = rows[: cutoff + 1]
        # If cutoff is None we fall through and return the full graph; the
        # API layer decides whether to 404 instead.

    return _project_rows(rows)


__all__ = [
    "AuditLineageEdge",
    "AuditLineageGraph",
    "AuditLineageNode",
    "build_audit_lineage",
]
