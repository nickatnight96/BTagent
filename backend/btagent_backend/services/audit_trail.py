"""SHA-256 chained immutable audit log service."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Any

from btagent_shared.types.enums import AuditCategory, AuditOutcome
from btagent_shared.utils.ids import generate_id
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import AuditLogRow

logger = logging.getLogger(__name__)

# The genesis (first) entry uses this sentinel as prev_hash.
_GENESIS_HASH = "0" * 64


def _compute_hash(
    id: str,
    seq: int,
    timestamp: str,
    actor: str,
    category: str,
    action: str,
    resource: str,
    outcome: str,
    details: str,
    prev_hash: str,
) -> str:
    payload = "|".join(
        [
            id,
            str(seq),
            timestamp,
            actor,
            category,
            action,
            resource,
            outcome,
            details,
            prev_hash,
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _details_to_canonical(details: dict[str, Any]) -> str:
    return json.dumps(details, sort_keys=True, default=str)


class AuditTrail:
    """SHA-256 chained, append-only audit log backed by the ``audit_logs`` table."""

    def __init__(self, db: AsyncSession):
        self._db = db

    async def record(
        self,
        actor: str,
        category: AuditCategory,
        action: str,
        resource: str = "",
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        details: dict[str, Any] | None = None,
    ) -> AuditLogRow:
        """Append a new entry to the audit chain.

        The entry's SHA-256 hash is computed over all fields plus the previous
        entry's hash, forming a tamper-evident chain similar to a blockchain.
        """
        details = details or {}
        entry_id = generate_id("aud")
        now = datetime.now(UTC)
        ts_iso = now.isoformat()

        # Fetch the latest entry to get prev_hash and next seq
        result = await self._db.execute(
            select(AuditLogRow).order_by(AuditLogRow.seq.desc()).limit(1)
        )
        prev_entry = result.scalar_one_or_none()

        if prev_entry is not None:
            prev_hash = prev_entry.hash
            seq = prev_entry.seq + 1
        else:
            prev_hash = _GENESIS_HASH
            seq = 1

        canonical_details = _details_to_canonical(details)

        entry_hash = _compute_hash(
            id=entry_id,
            seq=seq,
            timestamp=ts_iso,
            actor=actor,
            category=category.value,
            action=action,
            resource=resource,
            outcome=outcome.value,
            details=canonical_details,
            prev_hash=prev_hash,
        )

        row = AuditLogRow(
            id=entry_id,
            seq=seq,
            timestamp=now,
            actor=actor,
            category=category.value,
            action=action,
            resource=resource,
            outcome=outcome.value,
            details=details,
            prev_hash=prev_hash,
            hash=entry_hash,
        )
        self._db.add(row)
        await self._db.flush()

        logger.info(
            "Audit: seq=%d actor=%s category=%s action=%s outcome=%s",
            seq,
            actor,
            category.value,
            action,
            outcome.value,
        )
        return row

    async def verify_chain(self) -> tuple[bool, list[str]]:
        """Validate the full audit chain integrity.

        Returns a ``(valid, errors)`` tuple. ``errors`` contains human-readable
        descriptions of any integrity violations found.
        """
        errors: list[str] = []

        result = await self._db.execute(select(AuditLogRow).order_by(AuditLogRow.seq.asc()))
        rows = result.scalars().all()

        if not rows:
            return True, []

        # Verify the first entry links to the genesis sentinel
        first = rows[0]
        if first.prev_hash != _GENESIS_HASH:
            errors.append(
                f"seq={first.seq}: genesis entry prev_hash is "
                f"'{first.prev_hash}', expected '{_GENESIS_HASH}'"
            )

        prev_hash = _GENESIS_HASH
        for row in rows:
            # Verify chain linkage
            if row.prev_hash != prev_hash:
                errors.append(
                    f"seq={row.seq}: prev_hash mismatch "
                    f"(stored='{row.prev_hash}', expected='{prev_hash}')"
                )

            # Recompute the hash and verify. ``record()`` hashes a tz-aware
            # ISO string (``datetime.now(UTC)``); Postgres preserves the tz on
            # round-trip but SQLite drops it, so re-apply UTC to a naive value
            # to keep the recomputed hash byte-identical. This keeps
            # /audit/verify and /audit/lineage in agreement on every backend.
            canonical_details = _details_to_canonical(row.details or {})
            ts = row.timestamp
            if ts is not None and ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)
            ts_iso = ts.isoformat() if ts else ""

            expected_hash = _compute_hash(
                id=row.id,
                seq=row.seq,
                timestamp=ts_iso,
                actor=row.actor,
                category=row.category,
                action=row.action,
                resource=row.resource,
                outcome=row.outcome,
                details=canonical_details,
                prev_hash=row.prev_hash,
            )

            if row.hash != expected_hash:
                errors.append(
                    f"seq={row.seq}: hash mismatch "
                    f"(stored='{row.hash}', computed='{expected_hash}')"
                )

            prev_hash = row.hash

        valid = len(errors) == 0
        if not valid:
            logger.warning("Audit chain verification failed with %d error(s)", len(errors))
        else:
            logger.info("Audit chain verified: %d entries, all OK", len(rows))

        return valid, errors

    async def get_entries(
        self,
        *,
        actor: str | None = None,
        category: AuditCategory | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditLogRow]:
        """Query audit log entries with optional filters."""
        query = select(AuditLogRow).order_by(AuditLogRow.seq.desc())

        if actor is not None:
            query = query.where(AuditLogRow.actor == actor)
        if category is not None:
            query = query.where(AuditLogRow.category == category.value)

        query = query.offset(offset).limit(limit)
        result = await self._db.execute(query)
        return list(result.scalars().all())
