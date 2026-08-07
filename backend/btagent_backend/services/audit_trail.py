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
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID, AuditLogRow

logger = logging.getLogger(__name__)

# How many times an append re-reads ``seq`` and retries after losing the race
# to a concurrent writer. ``seq`` is UNIQUE, so a collision fails closed rather
# than forking the chain — but the entry must still land, because by the time
# an audit write runs the audited action has usually already happened. Five is
# well past what contention on a single-row read is expected to need; the point
# is a bound, so a pathological loop surfaces as an error instead of spinning.
_MAX_APPEND_ATTEMPTS = 5

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
    # JSON-encode the ordered field list rather than ``"|".join`` — a plain
    # delimiter is forgeable across free-text fields (actor="a|b" vs
    # actor="a", category="b" hash identically). JSON escaping makes the
    # boundary unambiguous. record() + both verifiers share this function, so
    # the chain stays self-consistent.
    payload = json.dumps(
        [id, seq, timestamp, actor, category, action, resource, outcome, details, prev_hash],
        separators=(",", ":"),
        ensure_ascii=False,
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
        *,
        org_id: str,
    ) -> AuditLogRow:
        """Append a new entry to the audit chain.

        The entry's SHA-256 hash is computed over all fields plus the previous
        entry's hash, forming a tamper-evident chain similar to a blockchain.

        GH #385: ``org_id`` stamps the writing tenant so the read surfaces can
        scope by org. It is *not* part of the hash — the chain stays a single
        global, tamper-evident sequence; org_id only governs read visibility.
        ``org_id`` is a **required keyword-only** argument (no default): every
        caller must pass the tenant of the entity being audited — API routes
        pass ``user.org_id``; service callers pass the audited row's ``org_id``.
        Making it required means an un-stamped write is a hard error at call
        time rather than silently landing in ``DEFAULT_ORG_ID`` — which would
        both hide the row from its own tenant's compliance ledger and disclose
        it to an ``org_default`` admin.
        """
        details = details or {}
        entry_id = generate_id("aud")
        canonical_details = _details_to_canonical(details)

        for attempt in range(_MAX_APPEND_ATTEMPTS):
            try:
                return await self._append_once(
                    entry_id=entry_id,
                    actor=actor,
                    category=category,
                    action=action,
                    resource=resource,
                    outcome=outcome,
                    details=details,
                    canonical_details=canonical_details,
                    org_id=org_id,
                )
            except IntegrityError:
                # Another writer took this ``seq`` between our read and our
                # insert. The UNIQUE constraint is what stops that becoming a
                # forked chain, so this is the constraint working — but the
                # entry still has to land, because by the time an audit write
                # runs the audited action has usually already happened.
                if attempt == _MAX_APPEND_ATTEMPTS - 1:
                    logger.error(
                        "audit append lost the seq race %d times for actor=%s action=%s; "
                        "the audited action is NOT on the ledger",
                        _MAX_APPEND_ATTEMPTS,
                        actor,
                        action,
                    )
                    raise
                logger.warning(
                    "audit append lost the seq race (attempt %d/%d); retrying",
                    attempt + 1,
                    _MAX_APPEND_ATTEMPTS,
                )
        raise AssertionError("unreachable")  # pragma: no cover

    async def _next_seq_and_prev_hash(self) -> tuple[int, str]:
        """The head of the chain: the next sequence number and what it links to.

        This read is the step that races. Two writers reaching it concurrently
        see the same head and derive the same ``seq``; ``UNIQUE(seq)`` then
        refuses the second insert. Named as its own method both because that is
        the racing step and because it gives a test a seam to return a stale
        head from, which is the only way to reproduce the collision on a
        single-writer SQLite suite.
        """
        result = await self._db.execute(
            select(AuditLogRow).order_by(AuditLogRow.seq.desc()).limit(1)
        )
        prev_entry = result.scalar_one_or_none()
        if prev_entry is None:
            return 1, _GENESIS_HASH
        return prev_entry.seq + 1, prev_entry.hash

    async def _append_once(
        self,
        *,
        entry_id: str,
        actor: str,
        category: AuditCategory,
        action: str,
        resource: str,
        outcome: AuditOutcome,
        details: dict[str, Any],
        canonical_details: str,
        org_id: str,
    ) -> AuditLogRow:
        """One read-compute-insert attempt, isolated behind a SAVEPOINT.

        The savepoint is what makes retrying possible at all. ``record`` is
        called mid-transaction with the caller's own writes pending, so a bare
        ``IntegrityError`` would poison the session and force a rollback that
        discards the caller's work — a containment action, say. Rolling back to
        a savepoint undoes only this failed insert.

        ``seq`` and ``prev_hash`` are re-read on every attempt: both are part
        of the hash, so a retry has to recompute the whole entry rather than
        re-submitting the same row with a new number.
        """
        now = datetime.now(UTC)
        ts_iso = now.isoformat()
        seq, prev_hash = await self._next_seq_and_prev_hash()

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
            org_id=org_id,
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
        # SAVEPOINT: a UNIQUE(seq) violation here rolls back only this insert,
        # leaving the caller's pending work intact so ``record`` can retry.
        async with self._db.begin_nested():
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

    async def verify_chain(self, org_id: str = DEFAULT_ORG_ID) -> tuple[bool, list[str]]:
        """Validate the audit chain integrity, scoped to one tenant.

        Returns a ``(valid, errors)`` tuple. ``errors`` contains human-readable
        descriptions of any integrity violations found.

        GH #385: the hash chain is a single *global* sequence — each entry's
        ``prev_hash`` links to whichever entry immediately precedes it, whatever
        its org. So linkage is verified over the full global chain (a per-org
        slice is not a valid chain on its own), but reported ``errors`` are
        scoped to the caller's ``org_id`` so one tenant can neither read nor
        infer another tenant's ledger contents.
        """
        errors: list[str] = []

        result = await self._db.execute(select(AuditLogRow).order_by(AuditLogRow.seq.asc()))
        rows = result.scalars().all()

        if not rows:
            return True, []

        # Verify the first entry links to the genesis sentinel — reported only
        # when that entry belongs to the caller's org.
        first = rows[0]
        if first.org_id == org_id and first.prev_hash != _GENESIS_HASH:
            errors.append(
                f"seq={first.seq}: genesis entry prev_hash is "
                f"'{first.prev_hash}', expected '{_GENESIS_HASH}'"
            )

        prev_hash = _GENESIS_HASH
        for row in rows:
            in_org = row.org_id == org_id

            # Verify chain linkage over the GLOBAL chain (prev_hash always
            # tracks the previous global row); surface it only for the caller.
            if in_org and row.prev_hash != prev_hash:
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

            if in_org and row.hash != expected_hash:
                errors.append(
                    f"seq={row.seq}: hash mismatch "
                    f"(stored='{row.hash}', computed='{expected_hash}')"
                )

            prev_hash = row.hash

        valid = len(errors) == 0
        if not valid:
            logger.warning("Audit chain verification failed with %d error(s)", len(errors))
        else:
            logger.info("Audit chain verified (org=%s): all OK", org_id)

        return valid, errors

    async def get_entries(
        self,
        *,
        org_id: str = DEFAULT_ORG_ID,
        actor: str | None = None,
        category: AuditCategory | None = None,
        resource: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditLogRow]:
        """Query audit log entries with optional filters.

        GH #385: always tenant-scoped — only entries for ``org_id`` are
        returned, so the /audit/entries and /audit/export surfaces never leak
        another org's ledger.

        ``resource`` narrows to a single audited object (EPIC-7 UC-7.1): it is
        how an auditor pulls one incident's evidence package rather than the
        whole org ledger. Matched exactly, not as a prefix — resource ids are
        prefixed ULIDs, so a substring match could pull unrelated objects.
        """
        query = (
            select(AuditLogRow).where(AuditLogRow.org_id == org_id).order_by(AuditLogRow.seq.desc())
        )

        if actor is not None:
            query = query.where(AuditLogRow.actor == actor)
        if category is not None:
            query = query.where(AuditLogRow.category == category.value)
        if resource is not None:
            query = query.where(AuditLogRow.resource == resource)

        query = query.offset(offset).limit(limit)
        result = await self._db.execute(query)
        return list(result.scalars().all())
