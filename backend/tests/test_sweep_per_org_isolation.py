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

from datetime import UTC, datetime

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


async def test_benign_reeval_sweep_continues_past_a_failing_org(_session_factory, monkeypatch):
    """The third sweep converted in #602 — same property, same shape.

    Its wrapper carried the same "best-effort and per-org isolated" docstring
    over the same single transaction, so it gets the same assertion rather
    than being trusted because the other two were fixed.
    """
    from btagent_backend.services import behavioral_service

    monkeypatch.setattr(
        behavioral_service,
        "org_ids_with_benign_outliers",
        _async_return(["org_b_bad", "org_b_good"]),
    )

    seen: list[str] = []

    async def _reeval(session, *, org_id, **kwargs):
        seen.append(org_id)
        if org_id == "org_b_bad":
            raise RuntimeError("simulated per-org failure")
        return behavioral_service.BenignDriftResult(orgs=1, entities_checked=4)

    monkeypatch.setattr(behavioral_service, "reevaluate_benign_labels", _reeval)

    counts = await jobs.behavioral_benign_reeval_sweep({})

    assert seen == ["org_b_bad", "org_b_good"]
    assert counts["entities_checked"] == 4
    # The failing org is counted as a failure, not silently dropped.
    assert counts["failures"] == 1


async def test_suppression_sweep_continues_past_a_failing_org(_session_factory, monkeypatch):
    """The last cron converted under #602 — the exemption list is now empty.

    ``sweep_stale_suppressions`` previously took no ``org_id`` and selected
    every tenant's ACTIVE rules in one transaction. Because the rules stay
    ACTIVE when the tick is lost, the next sweep re-ran from the same stale
    state — the flips never landed at all.
    """
    from btagent_backend.services import hunt_triage_service

    monkeypatch.setattr(
        hunt_triage_service,
        "org_ids_with_active_suppressions",
        _async_return(["org_s_bad", "org_s_good"]),
    )

    seen: list[str] = []

    async def _sweep(session, *, org_id, **kwargs):
        seen.append(org_id)
        if org_id == "org_s_bad":
            raise RuntimeError("simulated per-org failure")
        return {"scanned": 5, "expired": 2, "needs_reconfirm": 1}

    monkeypatch.setattr(hunt_triage_service, "sweep_stale_suppressions", _sweep)

    counts = await jobs.stale_suppression_sweep({})

    assert seen == ["org_s_bad", "org_s_good"]
    # Only the surviving org's flips are tallied; the failure neither counts
    # as success nor zeroes the tick.
    assert counts == {"scanned": 5, "expired": 2, "needs_reconfirm": 1}


async def test_the_suppression_org_filter_reaches_the_query(db_session):
    """Guard the guard: the ``org_id`` argument must actually scope the SELECT.

    A ``sweep_stale_suppressions`` that accepted ``org_id`` and ignored it
    would still satisfy the sweep test above — the first org's call would flip
    every tenant's rules, the second would find nothing left, and the totals
    would look identical. So assert the scoping behaviourally: seed an expired
    rule in two orgs, sweep only one, and check the other is untouched.

    Deliberately not a ``"...org_id" in inspect.getsource(...)`` check. That
    shape is what #603 had to replace, because a source-text test matches the
    prose in a docstring as happily as the code.
    """
    from btagent_backend.db.models_hunt import SuppressionRuleRow
    from btagent_backend.services import hunt_triage_service

    swept_org = "org_supp_swept"
    other_org = "org_supp_other"
    for org_id in (swept_org, other_org):
        db_session.add(OrganizationRow(id=org_id, name=f"Suppression {org_id}"))
    await db_session.flush()

    past = datetime(2020, 1, 1, tzinfo=UTC)
    for org_id in (swept_org, other_org):
        db_session.add(
            SuppressionRuleRow(
                id=f"supp_{org_id}",
                org_id=org_id,
                name=f"rule for {org_id}",
                reason="stale",
                match={},
                state="active",
                expires_at=past,
            )
        )
    await db_session.flush()

    counts = await hunt_triage_service.sweep_stale_suppressions(db_session, org_id=swept_org)

    assert counts["scanned"] == 1, "the sweep saw rules outside the org it was scoped to"
    assert counts["expired"] == 1

    untouched = await db_session.get(SuppressionRuleRow, f"supp_{other_org}")
    assert untouched is not None
    assert untouched.state == "active", "another tenant's rule was flipped by a scoped sweep"
