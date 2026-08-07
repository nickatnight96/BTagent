"""One tenant's failure must not discard another tenant's sweep work.

``_run_per_org`` exists because of a real incident, per its own docstring: a
single post-loop commit meant one malformed run discarded every previously
processed org's rows and re-notified from stale state on the next tick.

Two nightly sweeps had not been converted, and both *read* as though they had:

* ``memory_service.consolidate_all_orgs`` catches per-org and continues, which
  looks like isolation. It is not — one transaction covers the whole walk, so
  a failure raised from a *flush* leaves the session unusable and every later
  org plus the caller's commit fails with it. Catching an exception is not a
  transaction boundary.
* ``pattern_hunt_service.scan_all_orgs`` has no per-org handling at all, so one
  org raising aborted the entire weekly tick.

These tests assert the property at the level that was broken: after a sweep in
which one org fails, the *other* org's work is still committed. They drive the
real job functions rather than the service wrappers, because the commit
boundary is the job's responsibility and that is precisely what changed.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from btagent_backend.db.models import OrganizationRow
from btagent_backend.db.models_memory import AgentMemoryRow
from btagent_backend.scheduler import jobs


@pytest.fixture
def _session_factory(monkeypatch, db_session):
    """Point the jobs at the test session without closing it.

    The jobs use ``async with async_session_factory() as session``; handing
    back the fixture session directly would close it on exit and break later
    assertions, so wrap it in a no-op context manager.
    """

    class _Keep:
        async def __aenter__(self):
            return db_session

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(jobs, "async_session_factory", lambda: _Keep())
    return db_session


async def test_memory_sweep_keeps_a_healthy_orgs_work_when_another_org_fails(
    _session_factory, monkeypatch, db_session
):
    """The failing org is skipped; the healthy org's consolidation survives."""
    from btagent_backend.services import memory_service

    # A dedicated org for the healthy tenant, for two reasons. The write needs
    # a real row (``agent_memories.org_id`` is a FK), and using DEFAULT_ORG_ID
    # made the assertion below read every memory the rest of the suite had
    # seeded there — green alone, red in the full run. The failing tenant needs
    # no row: its whole job is to violate that FK at flush.
    good, bad = "org_sweep_healthy", "org_mem_bad"
    db_session.add(OrganizationRow(id=good, name="Sweep Isolation Healthy Tenant"))
    await db_session.commit()

    monkeypatch.setattr(
        memory_service,
        "org_ids_with_memories",
        _async_return([bad, good]),
    )

    seen: list[str] = []

    async def _consolidate(session, org_id, **kwargs):
        seen.append(org_id)
        if org_id == bad:
            # Fail at FLUSH, not before it. A plain ``raise`` here would leave
            # the session perfectly usable and the test would pass even under
            # the old single-commit shape — proving only "the loop continued".
            # The mechanism that actually loses the healthy org's work is a
            # failed flush poisoning the transaction, so reproduce that: an
            # org_id with no ``organizations`` row violates the FK on commit.
            session.add(
                AgentMemoryRow(
                    id="mem_orphan",
                    org_id=org_id,
                    kind="observation",
                    subject="orphan",
                    content="references a non-existent org",
                    tlp_level="green",
                )
            )
            return memory_service.ConsolidationResult(orgs=1)
        session.add(
            AgentMemoryRow(
                id=f"mem_{org_id}",
                org_id=org_id,
                kind="observation",
                subject="sweep-survivor",
                content="written by the healthy org",
                tlp_level="green",
            )
        )
        return memory_service.ConsolidationResult(orgs=1, scanned=1)

    monkeypatch.setattr(memory_service, "consolidate_memories", _consolidate)

    await jobs.memory_consolidation_sweep({})

    # Both orgs were attempted — a sweep that aborted on the first failure
    # would never have reached the healthy one.
    assert seen == [bad, good]

    # And the healthy org's row is committed, not rolled back alongside the
    # failure. This is the assertion the old single-commit shape failed.
    rows = (
        (await db_session.execute(select(AgentMemoryRow).where(AgentMemoryRow.org_id == good)))
        .scalars()
        .all()
    )
    assert [r.subject for r in rows] == ["sweep-survivor"]

    # The failing org wrote nothing.
    bad_rows = (
        (await db_session.execute(select(AgentMemoryRow).where(AgentMemoryRow.org_id == bad)))
        .scalars()
        .all()
    )
    assert bad_rows == []


async def test_pattern_scan_continues_past_a_failing_org(_session_factory, monkeypatch):
    """One org raising no longer aborts the whole weekly tick."""
    from btagent_backend.services import pattern_hunt_service

    monkeypatch.setattr(
        pattern_hunt_service,
        "list_org_ids",
        _async_return(["org_p_bad", "org_p_good"]),
    )

    seen: list[str] = []

    async def _scan(session, *, org_id, **kwargs):
        seen.append(org_id)
        if org_id == "org_p_bad":
            raise RuntimeError("simulated per-org failure")
        return pattern_hunt_service.PatternScanResult(investigations_scanned=3)

    monkeypatch.setattr(pattern_hunt_service, "scan_corpus", _scan)

    counts = await jobs.weekly_pattern_scan({})

    assert seen == ["org_p_bad", "org_p_good"]
    # Only the surviving org is counted — the failure is skipped, not tallied
    # as a success and not allowed to zero the tick.
    assert counts["orgs_scanned"] == 1
    assert counts["investigations_scanned"] == 3


def _async_return(value):
    async def _fn(*_args, **_kwargs):
        return value

    return _fn
