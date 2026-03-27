"""Tests for the SHA-256 hash-chain audit trail integrity.

These tests exercise the audit log model and the chain-linking logic
directly, without going through HTTP endpoints (which may not yet expose
an audit API). The hash chain guarantees tamper evidence: if any row is
altered after the fact, the chain breaks.
"""

import hashlib
import itertools
import json
from datetime import datetime, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import AuditLogRow
from btagent_shared.utils.ids import generate_id

# Global counter so every test gets unique seq values (audit_logs.seq is UNIQUE).
_seq_counter = itertools.count(1)


# ---------------------------------------------------------------------------
# Helpers -- reproducing the canonical hash computation
# ---------------------------------------------------------------------------

def _stable_ts(dt: datetime) -> str:
    """Return a timezone-naive ISO string so hashes survive SQLite round-trips.

    SQLite strips timezone info on storage, so we normalise here to avoid
    a mismatch between the original in-memory timestamp and the value read
    back from the database.
    """
    return dt.replace(tzinfo=None).isoformat()


def _canonical_payload(entry: AuditLogRow, prev_hash: str) -> str:
    """Build the canonical JSON string used to compute the chain hash."""
    return json.dumps(
        {
            "id": entry.id,
            "seq": entry.seq,
            "timestamp": _stable_ts(entry.timestamp),
            "actor": entry.actor,
            "category": entry.category,
            "action": entry.action,
            "resource": entry.resource,
            "outcome": entry.outcome,
            "prev_hash": prev_hash,
        },
        sort_keys=True,
    )


def _compute_hash(entry: AuditLogRow, prev_hash: str) -> str:
    payload = _canonical_payload(entry, prev_hash)
    return hashlib.sha256(payload.encode()).hexdigest()


async def _create_chained_entries(
    db: AsyncSession, count: int
) -> list[AuditLogRow]:
    """Insert ``count`` audit entries with a valid SHA-256 chain."""
    entries: list[AuditLogRow] = []
    prev_hash = ""

    for i in range(count):
        seq_val = next(_seq_counter)
        entry = AuditLogRow(
            id=generate_id("aud"),
            seq=seq_val,
            timestamp=datetime.now(timezone.utc),
            actor=f"usr_test_{i}",
            category="investigation",
            action=f"test_action_{i}",
            resource=f"inv_test_{i}",
            outcome="success",
            details={"step": i},
            prev_hash=prev_hash,
        )
        # Compute hash over the canonical representation.
        entry.hash = _compute_hash(entry, prev_hash)
        prev_hash = entry.hash

        db.add(entry)
        entries.append(entry)

    await db.commit()
    return entries


def _verify_chain(entries: list[AuditLogRow]) -> bool:
    """Re-compute and verify the hash chain over a list of entries."""
    prev_hash = entries[0].prev_hash if entries else ""
    for entry in entries:
        expected = _compute_hash(entry, prev_hash)
        if entry.hash != expected:
            return False
        if entry.prev_hash != prev_hash:
            return False
        prev_hash = entry.hash
    return True


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_chain_integrity_five_entries(db_session: AsyncSession):
    """Create 5 chained audit entries and verify the full chain."""
    entries = await _create_chained_entries(db_session, 5)
    assert len(entries) == 5
    assert _verify_chain(entries) is True


@pytest.mark.asyncio
async def test_audit_entry_stores_correct_fields(db_session: AsyncSession):
    """An audit entry stores all required fields correctly."""
    entries = await _create_chained_entries(db_session, 1)
    entry = entries[0]

    assert entry.id.startswith("aud_")
    assert isinstance(entry.seq, int)
    assert entry.seq > 0
    assert entry.actor == "usr_test_0"
    assert entry.category == "investigation"
    assert entry.action == "test_action_0"
    assert entry.resource == "inv_test_0"
    assert entry.outcome == "success"
    assert entry.details == {"step": 0}
    assert entry.prev_hash == ""  # First entry in this chain has no predecessor.
    assert len(entry.hash) == 64  # SHA-256 hex digest length.


@pytest.mark.asyncio
async def test_prev_hash_links_to_predecessor(db_session: AsyncSession):
    """Each entry's prev_hash matches the hash of its predecessor."""
    entries = await _create_chained_entries(db_session, 3)
    assert entries[0].prev_hash == ""
    assert entries[1].prev_hash == entries[0].hash
    assert entries[2].prev_hash == entries[1].hash


@pytest.mark.asyncio
async def test_chain_detects_action_tampering(db_session: AsyncSession):
    """Modifying the action field of a middle entry breaks the chain."""
    entries = await _create_chained_entries(db_session, 5)

    # Tamper with the third entry's action (index 2).
    entries[2].action = "tampered_action"

    assert _verify_chain(entries) is False


@pytest.mark.asyncio
async def test_chain_detects_actor_tampering(db_session: AsyncSession):
    """Modifying the actor field breaks the chain."""
    entries = await _create_chained_entries(db_session, 5)
    entries[1].actor = "usr_evil"
    assert _verify_chain(entries) is False


@pytest.mark.asyncio
async def test_chain_detects_hash_replacement(db_session: AsyncSession):
    """Replacing a hash value with an arbitrary string breaks the chain."""
    entries = await _create_chained_entries(db_session, 5)
    entries[3].hash = "a" * 64
    assert _verify_chain(entries) is False


@pytest.mark.asyncio
async def test_chain_detects_prev_hash_tampering(db_session: AsyncSession):
    """Changing prev_hash without recomputing hash breaks the chain."""
    entries = await _create_chained_entries(db_session, 5)
    entries[2].prev_hash = "b" * 64
    assert _verify_chain(entries) is False


@pytest.mark.asyncio
async def test_single_entry_chain_valid(db_session: AsyncSession):
    """A chain with a single entry is valid."""
    entries = await _create_chained_entries(db_session, 1)
    assert _verify_chain(entries) is True


@pytest.mark.asyncio
async def test_chain_entries_persist_in_db(db_session: AsyncSession):
    """Entries written to the DB can be read back and still verify."""
    entries = await _create_chained_entries(db_session, 4)
    entry_ids = [e.id for e in entries]

    # Flush the session identity map and re-query.
    db_session.expire_all()
    result = await db_session.execute(
        select(AuditLogRow)
        .where(AuditLogRow.id.in_(entry_ids))
        .order_by(AuditLogRow.seq)
    )
    reloaded = list(result.scalars().all())
    assert len(reloaded) == 4
    assert _verify_chain(reloaded) is True
