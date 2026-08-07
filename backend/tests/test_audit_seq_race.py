"""An audit append that loses the seq race must still land on the ledger.

`AuditTrail.record` derives `seq` by reading the current maximum and then
inserting. `audit_logs.seq` is UNIQUE — on the model *and* in migration 0001 —
so two concurrent writers cannot fork the chain: the second insert fails.
Failing closed is the right trade, a forked tamper-evident chain being far
worse than a failed insert.

But nothing handled that failure. The audit write is the **last** step of an
audited operation — `containment_execute_service.execute_response_action`
dispatches the containment action and *then* records — so the losing request
had already isolated the host when it raised. The action happened, no ledger
entry exists, and the caller was told it failed and may retry (#608).

## What these tests do and do not prove

They drive the collision deterministically: the first attempt's `seq` read is
made stale, so its insert hits the real UNIQUE constraint exactly as a
concurrent writer would. That exercises the mechanism that matters — savepoint
rollback, re-read, recompute, re-insert — and it does so against the real
constraint rather than a simulated one.

They do **not** prove behaviour under genuine concurrency. The backend suite
runs on in-memory SQLite with no concurrent writers, so no test here can. What
is verified is the recovery path; the race that triggers it is reproduced by
construction rather than by contention.
"""

from __future__ import annotations

import pytest
from btagent_shared.types.enums import AuditCategory, AuditOutcome
from sqlalchemy import select

from btagent_backend.db.models import DEFAULT_ORG_ID, AuditLogRow, InvestigationRow
from btagent_backend.services import audit_trail as audit_mod
from btagent_backend.services.audit_trail import AuditTrail


async def _record(db, action: str) -> AuditLogRow:
    return await AuditTrail(db).record(
        actor="tester",
        category=AuditCategory.CONTAINMENT,
        action=action,
        resource="host:web-01",
        outcome=AuditOutcome.SUCCESS,
        org_id=DEFAULT_ORG_ID,
    )


async def test_an_append_that_loses_the_seq_race_still_lands(db_session, monkeypatch):
    """The entry is written, with a fresh seq, after one real collision.

    The collision is produced by returning a **stale head** from
    ``_next_seq_and_prev_hash`` on the first attempt — the seq the previous
    entry already owns. That is precisely what a concurrent writer that read
    the same head would compute, and it hits the real ``UNIQUE(seq)``
    constraint rather than a stubbed one.
    """
    seed = await _record(db_session, "seed")
    await db_session.flush()

    real_head = AuditTrail._next_seq_and_prev_hash
    calls: list[int] = []

    async def _stale_first(self):
        calls.append(1)
        if len(calls) == 1:
            return seed.seq, seed.prev_hash  # already taken -> UNIQUE violation
        return await real_head(self)

    monkeypatch.setattr(AuditTrail, "_next_seq_and_prev_hash", _stale_first)

    entry = await _record(db_session, "isolate_host")

    assert len(calls) == 2, "the collision did not force a retry"
    stored = await db_session.get(AuditLogRow, entry.id)
    assert stored is not None, "the audited action left no ledger entry"
    assert stored.action == "isolate_host"
    assert stored.seq > seed.seq


async def test_the_callers_pending_work_survives_a_collision(db_session, monkeypatch):
    """The savepoint is the point: a retry must not discard the caller's writes.

    ``record`` runs mid-transaction with the audited action's own rows pending.
    Without a SAVEPOINT the IntegrityError poisons the session and the only
    recovery is a full rollback — which would throw away the very work the
    audit entry exists to describe.
    """
    seed = await _record(db_session, "seed")
    await db_session.flush()

    # A pending write standing in for the caller's audited work.
    db_session.add(
        InvestigationRow(
            id="inv_callers_pending_work",
            org_id=DEFAULT_ORG_ID,
            title="work the audit entry describes",
            description="",
            status="investigating",
            severity="medium",
            tlp_level="green",
        )
    )
    await db_session.flush()

    real_head = AuditTrail._next_seq_and_prev_hash
    calls: list[int] = []

    async def _stale_first(self):
        calls.append(1)
        if len(calls) == 1:
            return seed.seq, seed.prev_hash
        return await real_head(self)

    monkeypatch.setattr(AuditTrail, "_next_seq_and_prev_hash", _stale_first)

    await _record(db_session, "after-collision")

    assert len(calls) == 2
    survived = await db_session.get(InvestigationRow, "inv_callers_pending_work")
    assert survived is not None, (
        "the retry rolled back past its own savepoint and discarded the caller's work"
    )


async def test_the_append_gives_up_loudly_rather_than_spinning(db_session, monkeypatch):
    """A bounded retry: exhausting it raises instead of looping forever.

    Silently dropping the entry would be the worst outcome — the action
    happened and nothing says so. Raising at least surfaces it to the caller.
    """
    monkeypatch.setattr(audit_mod, "_MAX_APPEND_ATTEMPTS", 3)

    from sqlalchemy.exc import IntegrityError

    attempts: list[int] = []

    async def _always_collide(self, **kwargs):
        attempts.append(1)
        raise IntegrityError("stmt", {}, Exception("UNIQUE constraint failed: audit_logs.seq"))

    monkeypatch.setattr(AuditTrail, "_append_once", _always_collide)

    with pytest.raises(IntegrityError):
        await _record(db_session, "never-lands")

    assert len(attempts) == 3, "the bound is not being honoured"


async def test_a_normal_append_takes_exactly_one_attempt(db_session, monkeypatch):
    """Guard the guard: the retry must not fire on the uncontended path.

    A `record` that always retried would satisfy the tests above while doing
    twice the work on every audited operation — and would hide a real
    collision in the noise.
    """
    calls: list[int] = []
    real_append = AuditTrail._append_once

    async def _counting(self, **kwargs):
        calls.append(1)
        return await real_append(self, **kwargs)

    monkeypatch.setattr(AuditTrail, "_append_once", _counting)

    await _record(db_session, "uncontended")
    assert len(calls) == 1
